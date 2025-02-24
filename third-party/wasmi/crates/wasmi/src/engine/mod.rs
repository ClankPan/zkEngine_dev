//! The `wasmi` interpreter.

pub mod bytecode;
mod cache;
pub mod code_map;
mod config;
mod const_pool;
pub mod executor;
pub mod executor_v1;
mod func_args;
mod func_builder;
mod func_types;
mod regmach;
mod resumable;
pub mod stack;
mod traits;
mod translator;
mod trap;

#[cfg(test)]
mod tests;

#[cfg(test)]
use self::regmach::bytecode::RegisterSpan;

pub use self::{
    bytecode::DropKeep,
    code_map::CompiledFunc,
    config::{Config, EngineBackend, FuelConsumptionMode},
    func_builder::{Instr, RelativeDepth, TranslationError},
    resumable::{ResumableCall, ResumableInvocation, TypedResumableCall, TypedResumableInvocation},
    stack::StackLimits,
    traits::{CallParams, CallResults},
    translator::FuncBuilder,
};
use self::{
    bytecode::Instruction,
    cache::InstanceCache,
    code_map::CodeMap,
    const_pool::{ConstPool, ConstPoolView, ConstRef},
    executor::{execute_wasm, execute_wasm_with_trace_v0, WasmOutcome},
    func_types::FuncTypeRegistry,
    regmach::{
        bytecode::Instruction as Instruction2, code_map::CompiledFuncEntity, CodeMap as CodeMap2,
        FuncLocalConstsIter, Stack as Stack2,
    },
    resumable::ResumableCallBase,
    stack::{FuncFrame, Stack, ValueStack},
    trap::TaggedTrap,
};
pub(crate) use self::{
    config::FuelCosts,
    func_args::{FuncFinished, FuncParams, FuncResults},
    func_types::DedupFuncType,
    translator::ChosenFuncTranslatorAllocations,
};
use crate::engine::executor_v1::execute_wasm_with_trace;
use crate::{
    core::{Trap, TrapCode},
    func::{FuncEntity, WasmFuncEntity},
    AsContext, AsContextMut, Func, FuncType, StoreContextMut, Tracer, TracerV0,
};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};
use spin::{Mutex, RwLock};
use std::{cell::RefCell, rc::Rc};
use wasmi_arena::{ArenaIndex, GuardedEntity};
use wasmi_core::UntypedValue;

#[cfg(doc)]
use crate::Store;

/// A unique engine index.
///
/// # Note
///
/// Used to protect against invalid entity indices.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct EngineIdx(u32);

impl ArenaIndex for EngineIdx {
    fn into_usize(self) -> usize {
        self.0 as _
    }

    fn from_usize(value: usize) -> Self {
        let value = value.try_into().unwrap_or_else(|error| {
            panic!("index {value} is out of bounds as engine index: {error}")
        });
        Self(value)
    }
}

impl EngineIdx {
    /// Returns a new unique [`EngineIdx`].
    fn new() -> Self {
        /// A static store index counter.
        static CURRENT_STORE_IDX: AtomicU32 = AtomicU32::new(0);
        let next_idx = CURRENT_STORE_IDX.fetch_add(1, Ordering::AcqRel);
        Self(next_idx)
    }
}

/// An entity owned by the [`Engine`].
type Guarded<Idx> = GuardedEntity<EngineIdx, Idx>;

/// The `wasmi` interpreter.
///
/// # Note
///
/// - The current `wasmi` engine implements a bytecode interpreter.
/// - This structure is intentionally cheap to copy.
///   Most of its API has a `&self` receiver, so can be shared easily.
#[derive(Debug, Clone)]
pub struct Engine {
    inner: Arc<EngineInner>,
}

impl Default for Engine {
    fn default() -> Self {
        Self::new(&Config::default())
    }
}

impl Engine {
    /// Creates a new [`Engine`] with default configuration.
    ///
    /// # Note
    ///
    /// Users should ues [`Engine::default`] to construct a default [`Engine`].
    pub fn new(config: &Config) -> Self {
        Self {
            inner: Arc::new(EngineInner::new(config)),
        }
    }

    /// Returns a shared reference to the [`Config`] of the [`Engine`].
    pub fn config(&self) -> &Config {
        self.inner.config()
    }

    /// Returns `true` if both [`Engine`] references `a` and `b` refer to the same [`Engine`].
    pub fn same(a: &Engine, b: &Engine) -> bool {
        Arc::ptr_eq(&a.inner, &b.inner)
    }

    /// Allocates a new function type to the [`Engine`].
    pub(super) fn alloc_func_type(&self, func_type: FuncType) -> DedupFuncType {
        self.inner.alloc_func_type(func_type)
    }

    /// Resolves a deduplicated function type into a [`FuncType`] entity.
    ///
    /// # Panics
    ///
    /// - If the deduplicated function type is not owned by the engine.
    /// - If the deduplicated function type cannot be resolved to its entity.
    pub(super) fn resolve_func_type<F, R>(&self, func_type: &DedupFuncType, f: F) -> R
    where
        F: FnOnce(&FuncType) -> R,
    {
        self.inner.resolve_func_type(func_type, f)
    }

    /// Allocates a new constant value to the [`Engine`].
    ///
    /// # Errors
    ///
    /// If too many constant values have been allocated for the [`Engine`] this way.
    pub(super) fn alloc_const(
        &self,
        value: impl Into<UntypedValue>,
    ) -> Result<ConstRef, TranslationError> {
        self.inner.alloc_const(value.into())
    }

    /// Allocates a new uninitialized [`CompiledFunc`] to the [`Engine`].
    ///
    /// Returns a [`CompiledFunc`] reference to allow accessing the allocated [`CompiledFunc`].
    pub(super) fn alloc_func(&self) -> CompiledFunc {
        self.inner.alloc_func()
    }

    /// Allocates a new uninitialized [`CompiledFunc`] to the [`Engine`].
    ///
    /// Returns a [`CompiledFunc`] reference to allow accessing the allocated [`CompiledFunc`].
    pub(super) fn alloc_func_2(&self) -> CompiledFunc {
        self.inner.alloc_func_2()
    }

    /// Initializes the uninitialized [`CompiledFunc`] for the [`Engine`].
    ///
    /// # Panics
    ///
    /// - If `func` is an invalid [`CompiledFunc`] reference for this [`CodeMap`].
    /// - If `func` refers to an already initialized [`CompiledFunc`].
    pub(super) fn init_func<I>(
        &self,
        func: CompiledFunc,
        len_locals: usize,
        local_stack_height: usize,
        instrs: I,
    ) where
        I: IntoIterator<Item = Instruction>,
    {
        self.inner
            .init_func(func, len_locals, local_stack_height, instrs)
    }

    /// Initializes the uninitialized [`CompiledFunc`] for the [`Engine`].
    ///
    /// # Panics
    ///
    /// - If `func` is an invalid [`CompiledFunc`] reference for this [`CodeMap`].
    /// - If `func` refers to an already initialized [`CompiledFunc`].
    fn init_func_2<I>(
        &self,
        func: CompiledFunc,
        len_registers: u16,
        len_results: u16,
        func_locals: FuncLocalConstsIter,
        instrs: I,
    ) where
        I: IntoIterator<Item = Instruction2>,
    {
        self.inner
            .init_func_2(func, len_registers, len_results, func_locals, instrs)
    }

    /// Resolves the [`CompiledFuncEntity`] for [`CompiledFunc`] and applies `f` to it.
    ///
    /// # Panics
    ///
    /// If [`CompiledFunc`] is invalid for [`Engine`].
    pub(super) fn resolve_func_2<F, R>(&self, func: CompiledFunc, f: F) -> R
    where
        F: FnOnce(&CompiledFuncEntity) -> R,
    {
        self.inner.resolve_func_2(func, f)
    }

    /// Resolves the [`CompiledFunc`] to the underlying `wasmi` bytecode instructions.
    ///
    /// # Note
    ///
    /// - This API is mainly intended for unit testing purposes and shall not be used
    ///   outside of this context. The function bodies are intended to be data private
    ///   to the `wasmi` interpreter.
    ///
    /// # Panics
    ///
    /// If the [`CompiledFunc`] is invalid for the [`Engine`].
    #[cfg(test)]
    pub(crate) fn resolve_instr(
        &self,
        func_body: CompiledFunc,
        index: usize,
    ) -> Option<Instruction> {
        self.inner.resolve_instr(func_body, index)
    }

    /// Resolves the [`CompiledFunc`] to the underlying `wasmi` bytecode instructions.
    ///
    /// # Note
    ///
    /// - This is a variant of [`Engine::resolve_instr`] that returns register
    ///   machine based bytecode instructions.
    /// - This API is mainly intended for unit testing purposes and shall not be used
    ///   outside of this context. The function bodies are intended to be data private
    ///   to the `wasmi` interpreter.
    ///
    /// # Panics
    ///
    /// - If the [`CompiledFunc`] is invalid for the [`Engine`].
    /// - If register machine bytecode translation is disabled.
    #[cfg(test)]
    pub(crate) fn resolve_instr_2(&self, func: CompiledFunc, index: usize) -> Option<Instruction2> {
        self.inner.resolve_instr_2(func, index)
    }

    /// Resolves the function local constant of [`CompiledFunc`] at `index` if any.
    ///
    /// # Note
    ///
    /// This API is intended for unit testing purposes and shall not be used
    /// outside of this context. The function bodies are intended to be data
    /// private to the `wasmi` interpreter.
    ///
    /// # Panics
    ///
    /// - If the [`CompiledFunc`] is invalid for the [`Engine`].
    /// - If register machine bytecode translation is disabled.
    #[cfg(test)]
    fn get_func_const_2(&self, func: CompiledFunc, index: usize) -> Option<UntypedValue> {
        self.inner.get_func_const_2(func, index)
    }

    /// Executes the given [`Func`] with parameters `params`.
    ///
    /// Stores the execution result into `results` upon a successful execution.
    ///
    /// # Note
    ///
    /// - Assumes that the `params` and `results` are well typed.
    ///   Type checks are done at the [`Func::call`] API or when creating
    ///   a new [`TypedFunc`] instance via [`Func::typed`].
    /// - The `params` out parameter is in a valid but unspecified state if this
    ///   function returns with an error.
    ///
    /// # Errors
    ///
    /// - If `params` are overflowing or underflowing the expected amount of parameters.
    /// - If the given `results` do not match the the length of the expected results of `func`.
    /// - When encountering a Wasm or host trap during the execution of `func`.
    ///
    /// [`TypedFunc`]: [`crate::TypedFunc`]
    #[inline]
    pub(crate) fn execute_func<T, Results>(
        &self,
        ctx: StoreContextMut<T>,
        func: &Func,
        params: impl CallParams,
        results: Results,
    ) -> Result<<Results as CallResults>::Results, Trap>
    where
        Results: CallResults,
    {
        self.inner.execute_func(ctx, func, params, results)
    }

    /// Executes the given [`Func`] with parameters `params`.
    ///
    /// Stores the execution result into `results` upon a successful execution.
    ///
    /// # Note
    ///
    /// - Assumes that the `params` and `results` are well typed.
    ///   Type checks are done at the [`Func::call`] API or when creating
    ///   a new [`TypedFunc`] instance via [`Func::typed`].
    /// - The `params` out parameter is in a valid but unspecified state if this
    ///   function returns with an error.
    ///
    /// # Errors
    ///
    /// - If `params` are overflowing or underflowing the expected amount of parameters.
    /// - If the given `results` do not match the the length of the expected results of `func`.
    /// - When encountering a Wasm or host trap during the execution of `func`.
    ///
    /// [`TypedFunc`]: [`crate::TypedFunc`]
    #[inline]
    pub(crate) fn execute_func_with_trace<T, Results>(
        &self,
        ctx: StoreContextMut<T>,
        func: &Func,
        params: impl CallParams,
        results: Results,
        tracer: Rc<RefCell<Tracer>>,
    ) -> Result<<Results as CallResults>::Results, Trap>
    where
        Results: CallResults,
    {
        self.inner
            .execute_func_with_trace(ctx, func, params, results, tracer)
    }

    /// Executes the given [`Func`] with parameters `params`.
    ///
    /// Stores the execution result into `results` upon a successful execution.
    ///
    /// # Note
    ///
    /// - Assumes that the `params` and `results` are well typed.
    ///   Type checks are done at the [`Func::call`] API or when creating
    ///   a new [`TypedFunc`] instance via [`Func::typed`].
    /// - The `params` out parameter is in a valid but unspecified state if this
    ///   function returns with an error.
    ///
    /// # Errors
    ///
    /// - If `params` are overflowing or underflowing the expected amount of parameters.
    /// - If the given `results` do not match the the length of the expected results of `func`.
    /// - When encountering a Wasm or host trap during the execution of `func`.
    ///
    /// [`TypedFunc`]: [`crate::TypedFunc`]
    #[inline]
    pub(crate) fn execute_func_with_trace_v0<T, Results>(
        &self,
        ctx: StoreContextMut<T>,
        func: &Func,
        params: impl CallParams,
        results: Results,
        tracer: Rc<RefCell<TracerV0>>,
    ) -> Result<<Results as CallResults>::Results, Trap>
    where
        Results: CallResults,
    {
        self.inner
            .execute_func_with_trace_v0(ctx, func, params, results, tracer)
    }

    /// Executes the given [`Func`] resumably with parameters `params` and returns.
    ///
    /// Stores the execution result into `results` upon a successful execution.
    /// If the execution encounters a host trap it will return a handle to the user
    /// that allows to resume the execution at that point.
    ///
    /// # Note
    ///
    /// - Assumes that the `params` and `results` are well typed.
    ///   Type checks are done at the [`Func::call`] API or when creating
    ///   a new [`TypedFunc`] instance via [`Func::typed`].
    /// - The `params` out parameter is in a valid but unspecified state if this
    ///   function returns with an error.
    ///
    /// # Errors
    ///
    /// - If `params` are overflowing or underflowing the expected amount of parameters.
    /// - If the given `results` do not match the the length of the expected results of `func`.
    /// - When encountering a Wasm trap during the execution of `func`.
    /// - When `func` is a host function that traps.
    ///
    /// [`TypedFunc`]: [`crate::TypedFunc`]
    #[inline]
    pub(crate) fn execute_func_resumable<T, Results>(
        &self,
        ctx: StoreContextMut<T>,
        func: &Func,
        params: impl CallParams,
        results: Results,
    ) -> Result<ResumableCallBase<<Results as CallResults>::Results>, Trap>
    where
        Results: CallResults,
    {
        self.inner
            .execute_func_resumable(ctx, func, params, results)
    }

    /// Resumes the given `invocation` given the `params`.
    ///
    /// Stores the execution result into `results` upon a successful execution.
    /// If the execution encounters a host trap it will return a handle to the user
    /// that allows to resume the execution at that point.
    ///
    /// # Note
    ///
    /// - Assumes that the `params` and `results` are well typed.
    ///   Type checks are done at the [`Func::call`] API or when creating
    ///   a new [`TypedFunc`] instance via [`Func::typed`].
    /// - The `params` out parameter is in a valid but unspecified state if this
    ///   function returns with an error.
    ///
    /// # Errors
    ///
    /// - If `params` are overflowing or underflowing the expected amount of parameters.
    /// - If the given `results` do not match the the length of the expected results of `func`.
    /// - When encountering a Wasm trap during the execution of `func`.
    /// - When `func` is a host function that traps.
    ///
    /// [`TypedFunc`]: [`crate::TypedFunc`]
    #[inline]
    pub(crate) fn resume_func<T, Results>(
        &self,
        ctx: StoreContextMut<T>,
        invocation: ResumableInvocation,
        params: impl CallParams,
        results: Results,
    ) -> Result<ResumableCallBase<<Results as CallResults>::Results>, Trap>
    where
        Results: CallResults,
    {
        self.inner.resume_func(ctx, invocation, params, results)
    }

    /// Recycles the given [`Stack`] for reuse in the [`Engine`].
    pub(crate) fn recycle_stack(&self, stack: Stack) {
        self.inner.recycle_stack(stack)
    }

    /// Recycles the given [`Stack`] for reuse in the [`Engine`].
    pub(crate) fn recycle_stack_2(&self, stack: Stack2) {
        self.inner.recycle_stack_2(stack)
    }
}

/// The internal state of the `wasmi` [`Engine`].
#[derive(Debug)]
pub struct EngineInner {
    /// The [`Config`] of the engine.
    config: Config,
    /// Engine resources shared across multiple engine executors.
    res: RwLock<EngineResources>,
    /// Reusable engine stacks for Wasm execution.
    ///
    /// Concurrently executing Wasm executions each require their own stack to
    /// operate on. Therefore a Wasm engine is required to provide stacks and
    /// ideally recycles old ones since creation of a new stack is rather expensive.
    stacks: Mutex<EngineStacks>,
}

/// The engine's stacks for reuse.
///
/// Rquired for efficient concurrent Wasm executions.
#[derive(Debug)]
pub struct EngineStacks {
    /// Stacks to be (re)used.
    stacks: Vec<Stack>,
    /// Stacks to be (re)used.
    ///
    /// # Note
    ///
    /// These are the stack used by the register-machine `wasmi` implementation.
    stacks2: Vec<Stack2>,
    /// Stack limits for newly constructed engine stacks.
    limits: StackLimits,
    /// How many stacks should be kept for reuse at most.
    keep: usize,
}

impl EngineStacks {
    /// Creates new [`EngineStacks`] with the given [`StackLimits`].
    pub fn new(config: &Config) -> Self {
        Self {
            stacks: Vec::new(),
            stacks2: Vec::new(),
            limits: config.stack_limits(),
            keep: config.cached_stacks(),
        }
    }

    /// Reuse or create a new [`Stack`] if none was available.
    pub fn reuse_or_new(&mut self) -> Stack {
        match self.stacks.pop() {
            Some(stack) => stack,
            None => Stack::new(self.limits),
        }
    }

    /// Reuse or create a new [`Stack`] if none was available.
    pub fn reuse_or_new_2(&mut self) -> Stack2 {
        match self.stacks2.pop() {
            Some(stack) => stack,
            None => Stack2::new(self.limits),
        }
    }

    /// Disose and recycle the `stack`.
    pub fn recycle(&mut self, stack: Stack) {
        if !stack.is_empty() && self.stacks.len() < self.keep {
            self.stacks.push(stack);
        }
    }

    /// Disose and recycle the `stack`.
    pub fn recycle_2(&mut self, stack: Stack2) {
        if !stack.is_empty() && self.stacks2.len() < self.keep {
            self.stacks2.push(stack);
        }
    }
}

impl EngineInner {
    /// Creates a new [`EngineInner`] with the given [`Config`].
    fn new(config: &Config) -> Self {
        Self {
            config: *config,
            res: RwLock::new(EngineResources::new()),
            stacks: Mutex::new(EngineStacks::new(config)),
        }
    }

    /// Returns a shared reference to the [`Config`] of the [`EngineInner`].
    fn config(&self) -> &Config {
        &self.config
    }

    /// Allocates a new function type to the [`EngineInner`].
    fn alloc_func_type(&self, func_type: FuncType) -> DedupFuncType {
        self.res.write().func_types.alloc_func_type(func_type)
    }

    /// Resolves a deduplicated function type into a [`FuncType`] entity.
    ///
    /// # Panics
    ///
    /// - If the deduplicated function type is not owned by the engine.
    /// - If the deduplicated function type cannot be resolved to its entity.
    fn resolve_func_type<F, R>(&self, func_type: &DedupFuncType, f: F) -> R
    where
        F: FnOnce(&FuncType) -> R,
    {
        f(self.res.read().func_types.resolve_func_type(func_type))
    }

    /// Allocates a new constant value to the [`EngineInner`].
    ///
    /// # Errors
    ///
    /// If too many constant values have been allocated for the [`EngineInner`] this way.
    fn alloc_const(&self, value: UntypedValue) -> Result<ConstRef, TranslationError> {
        self.res.write().const_pool.alloc(value)
    }

    /// Allocates a new uninitialized [`CompiledFunc`] to the [`EngineInner`].
    ///
    /// Returns a [`CompiledFunc`] reference to allow accessing the allocated [`CompiledFunc`].
    fn alloc_func(&self) -> CompiledFunc {
        self.res.write().code_map.alloc_func()
    }

    /// Allocates a new uninitialized [`CompiledFunc`] to the [`EngineInner`].
    ///
    /// Returns a [`CompiledFunc`] reference to allow accessing the allocated [`CompiledFunc`].
    fn alloc_func_2(&self) -> CompiledFunc {
        self.res.write().code_map_2.alloc_func()
    }

    /// Initializes the uninitialized [`CompiledFunc`] for the [`EngineInner`].
    ///
    /// # Panics
    ///
    /// - If `func` is an invalid [`CompiledFunc`] reference for this [`CodeMap`].
    /// - If `func` refers to an already initialized [`CompiledFunc`].
    fn init_func<I>(
        &self,
        func: CompiledFunc,
        len_locals: usize,
        local_stack_height: usize,
        instrs: I,
    ) where
        I: IntoIterator<Item = Instruction>,
    {
        self.res
            .write()
            .code_map
            .init_func(func, len_locals, local_stack_height, instrs)
    }

    /// Initializes the uninitialized [`CompiledFunc`] for the [`EngineInner`].
    ///
    /// # Panics
    ///
    /// - If `func` is an invalid [`CompiledFunc`] reference for this [`CodeMap`].
    /// - If `func` refers to an already initialized [`CompiledFunc`].
    fn init_func_2<I>(
        &self,
        func: CompiledFunc,
        len_registers: u16,
        len_results: u16,
        func_locals: FuncLocalConstsIter,
        instrs: I,
    ) where
        I: IntoIterator<Item = Instruction2>,
    {
        self.res
            .write()
            .code_map_2
            .init_func(func, len_registers, len_results, func_locals, instrs)
    }

    /// Resolves the [`CompiledFuncEntity`] for [`CompiledFunc`] and applies `f` to it.
    ///
    /// # Panics
    ///
    /// If [`CompiledFunc`] is invalid for [`Engine`].
    pub(super) fn resolve_func_2<F, R>(&self, func: CompiledFunc, f: F) -> R
    where
        F: FnOnce(&CompiledFuncEntity) -> R,
    {
        f(self.res.read().code_map_2.get(func))
    }

    #[cfg(test)]
    fn resolve_instr(&self, func_body: CompiledFunc, index: usize) -> Option<Instruction> {
        self.res
            .read()
            .code_map
            .get_instr(func_body, index)
            .copied()
    }

    #[cfg(test)]
    pub(crate) fn resolve_instr_2(&self, func: CompiledFunc, index: usize) -> Option<Instruction2> {
        self.res
            .read()
            .code_map_2
            .get(func)
            .instrs()
            .get(index)
            .copied()
    }

    #[cfg(test)]
    fn get_func_const_2(&self, func: CompiledFunc, index: usize) -> Option<UntypedValue> {
        // Function local constants are stored in reverse order of their indices since
        // they are allocated in reverse order to their absolute indices during function
        // translation. That is why we need to access them in reverse order.
        self.res
            .read()
            .code_map_2
            .get(func)
            .consts()
            .iter()
            .rev()
            .nth(index)
            .copied()
    }

    /// Executes the given [`Func`] with the given `params` and returns the `results`.
    ///
    /// Uses the [`StoreContextMut`] for context information about the Wasm [`Store`].
    ///
    /// # Errors
    ///
    /// If the Wasm execution traps or runs out of resources.
    fn execute_func<T, Results>(
        &self,
        ctx: StoreContextMut<T>,
        func: &Func,
        params: impl CallParams,
        results: Results,
    ) -> Result<<Results as CallResults>::Results, Trap>
    where
        Results: CallResults,
    {
        match self.config().engine_backend() {
            EngineBackend::StackMachine => self.execute_func_stackmach(ctx, func, params, results),
            EngineBackend::RegisterMachine => self.execute_func_regmach(ctx, func, params, results),
        }
    }

    /// Executes the given [`Func`] with the given `params` and returns the `results`.
    ///
    /// Uses the [`StoreContextMut`] for context information about the Wasm [`Store`].
    ///
    /// # Errors
    ///
    /// If the Wasm execution traps or runs out of resources.
    fn execute_func_with_trace<T, Results>(
        &self,
        ctx: StoreContextMut<T>,
        func: &Func,
        params: impl CallParams,
        results: Results,
        tracer: Rc<RefCell<Tracer>>,
    ) -> Result<<Results as CallResults>::Results, Trap>
    where
        Results: CallResults,
    {
        match self.config().engine_backend() {
            EngineBackend::StackMachine => {
                self.execute_func_stackmach_with_trace(ctx, func, params, results, tracer)
            }
            EngineBackend::RegisterMachine => self.execute_func_regmach(ctx, func, params, results),
        }
    }

    /// Executes the given [`Func`] with the given `params` and returns the `results`.
    ///
    /// Uses the [`StoreContextMut`] for context information about the Wasm [`Store`].
    ///
    /// # Errors
    ///
    /// If the Wasm execution traps or runs out of resources.
    fn execute_func_with_trace_v0<T, Results>(
        &self,
        ctx: StoreContextMut<T>,
        func: &Func,
        params: impl CallParams,
        results: Results,
        tracer: Rc<RefCell<TracerV0>>,
    ) -> Result<<Results as CallResults>::Results, Trap>
    where
        Results: CallResults,
    {
        match self.config().engine_backend() {
            EngineBackend::StackMachine => {
                self.execute_func_stackmach_with_trace_v0(ctx, func, params, results, tracer)
            }
            EngineBackend::RegisterMachine => self.execute_func_regmach(ctx, func, params, results),
        }
    }

    /// Executes the given [`Func`] with the given `params` and returns the `results`.
    ///
    /// - Uses the `wasmi` stack-machine based engine backend.
    /// - Uses the [`StoreContextMut`] for context information about the Wasm [`Store`].
    ///
    /// # Errors
    ///
    /// If the Wasm execution traps or runs out of resources.
    fn execute_func_stackmach<T, Results>(
        &self,
        ctx: StoreContextMut<T>,
        func: &Func,
        params: impl CallParams,
        results: Results,
    ) -> Result<<Results as CallResults>::Results, Trap>
    where
        Results: CallResults,
    {
        let res = self.res.read();
        let mut stack = self.stacks.lock().reuse_or_new();
        let results = EngineExecutor::new(&res, &mut stack)
            .execute_func(ctx, func, params, results)
            .map_err(TaggedTrap::into_trap);
        self.stacks.lock().recycle(stack);
        results
    }

    /// Executes the given [`Func`] with the given `params` and returns the `results`.
    ///
    /// - Uses the `wasmi` stack-machine based engine backend.
    /// - Uses the [`StoreContextMut`] for context information about the Wasm [`Store`].
    ///
    /// # Errors
    ///
    /// If the Wasm execution traps or runs out of resources.
    fn execute_func_stackmach_with_trace<T, Results>(
        &self,
        ctx: StoreContextMut<T>,
        func: &Func,
        params: impl CallParams,
        results: Results,
        tracer: Rc<RefCell<Tracer>>,
    ) -> Result<<Results as CallResults>::Results, Trap>
    where
        Results: CallResults,
    {
        let res = self.res.read();
        let mut stack = self.stacks.lock().reuse_or_new();
        let results = EngineExecutor::new(&res, &mut stack)
            .execute_func_with_trace(ctx, func, params, results, tracer)
            .map_err(TaggedTrap::into_trap);
        self.stacks.lock().recycle(stack);
        results
    }

    /// Executes the given [`Func`] with the given `params` and returns the `results`.
    ///
    /// - Uses the `wasmi` stack-machine based engine backend.
    /// - Uses the [`StoreContextMut`] for context information about the Wasm [`Store`].
    ///
    /// # Errors
    ///
    /// If the Wasm execution traps or runs out of resources.
    fn execute_func_stackmach_with_trace_v0<T, Results>(
        &self,
        ctx: StoreContextMut<T>,
        func: &Func,
        params: impl CallParams,
        results: Results,
        tracer: Rc<RefCell<TracerV0>>,
    ) -> Result<<Results as CallResults>::Results, Trap>
    where
        Results: CallResults,
    {
        let res = self.res.read();
        let mut stack = self.stacks.lock().reuse_or_new();
        let results = EngineExecutor::new(&res, &mut stack)
            .execute_func_with_trace_v0(ctx, func, params, results, tracer)
            .map_err(TaggedTrap::into_trap);
        self.stacks.lock().recycle(stack);
        results
    }

    /// Executes the given [`Func`] resumably with the given `params` and returns the `results`.
    ///
    /// Uses the [`StoreContextMut`] for context information about the Wasm [`Store`].
    ///
    /// # Errors
    ///
    /// If the Wasm execution traps or runs out of resources.
    fn execute_func_resumable<T, Results>(
        &self,
        ctx: StoreContextMut<T>,
        func: &Func,
        params: impl CallParams,
        results: Results,
    ) -> Result<ResumableCallBase<<Results as CallResults>::Results>, Trap>
    where
        Results: CallResults,
    {
        match self.config().engine_backend() {
            EngineBackend::StackMachine => {
                self.execute_func_resumable_stackmach(ctx, func, params, results)
            }
            EngineBackend::RegisterMachine => {
                self.execute_func_resumable_regmach(ctx, func, params, results)
            }
        }
    }

    /// Executes the given [`Func`] resumably with the given `params` and returns the `results`.
    ///
    /// - Uses the `wasmi` stack-machine based engine backend.
    /// - Uses the [`StoreContextMut`] for context information about the Wasm [`Store`].
    ///
    /// # Errors
    ///
    /// If the Wasm execution traps or runs out of resources.
    fn execute_func_resumable_stackmach<T, Results>(
        &self,
        mut ctx: StoreContextMut<T>,
        func: &Func,
        params: impl CallParams,
        results: Results,
    ) -> Result<ResumableCallBase<<Results as CallResults>::Results>, Trap>
    where
        Results: CallResults,
    {
        let res = self.res.read();
        let mut stack = self.stacks.lock().reuse_or_new();
        let results = EngineExecutor::new(&res, &mut stack).execute_func(
            ctx.as_context_mut(),
            func,
            params,
            results,
        );
        match results {
            Ok(results) => {
                self.stacks.lock().recycle(stack);
                Ok(ResumableCallBase::Finished(results))
            }
            Err(TaggedTrap::Wasm(trap)) => {
                self.stacks.lock().recycle(stack);
                Err(trap)
            }
            Err(TaggedTrap::Host {
                host_func,
                host_trap,
            }) => Ok(ResumableCallBase::Resumable(ResumableInvocation::new(
                ctx.as_context().store.engine().clone(),
                *func,
                host_func,
                host_trap,
                None,
                stack,
            ))),
        }
    }

    /// Resumes the given [`Func`] with the given `params` and returns the `results`.
    ///
    /// - Uses the [`StoreContextMut`] for context information about the Wasm [`Store`].
    ///
    /// # Errors
    ///
    /// If the Wasm execution traps or runs out of resources.
    fn resume_func<T, Results>(
        &self,
        ctx: StoreContextMut<T>,
        invocation: ResumableInvocation,
        params: impl CallParams,
        results: Results,
    ) -> Result<ResumableCallBase<<Results as CallResults>::Results>, Trap>
    where
        Results: CallResults,
    {
        match self.config().engine_backend() {
            EngineBackend::StackMachine => {
                self.resume_func_stackmach(ctx, invocation, params, results)
            }
            EngineBackend::RegisterMachine => {
                self.resume_func_regmach(ctx, invocation, params, results)
            }
        }
    }

    /// Resumes the given [`Func`] with the given `params` and returns the `results`.
    ///
    /// - Uses the `wasmi` stack-machine based engine backend.
    /// - Uses the [`StoreContextMut`] for context information about the Wasm [`Store`].
    ///
    /// # Errors
    ///
    /// If the Wasm execution traps or runs out of resources.
    fn resume_func_stackmach<T, Results>(
        &self,
        ctx: StoreContextMut<T>,
        mut invocation: ResumableInvocation,
        params: impl CallParams,
        results: Results,
    ) -> Result<ResumableCallBase<<Results as CallResults>::Results>, Trap>
    where
        Results: CallResults,
    {
        let res = self.res.read();
        let host_func = invocation.host_func();
        let mut stack = invocation.take_stack().into_stackmach();
        let results =
            EngineExecutor::new(&res, &mut stack).resume_func(ctx, host_func, params, results);
        match results {
            Ok(results) => {
                self.stacks.lock().recycle(stack);
                Ok(ResumableCallBase::Finished(results))
            }
            Err(TaggedTrap::Wasm(trap)) => {
                self.stacks.lock().recycle(stack);
                Err(trap)
            }
            Err(TaggedTrap::Host {
                host_func,
                host_trap,
            }) => {
                invocation.update(stack, host_func, host_trap);
                Ok(ResumableCallBase::Resumable(invocation))
            }
        }
    }

    /// Recycles the given [`Stack`] for the stack-machine `wasmi` engine backend.
    fn recycle_stack(&self, stack: Stack) {
        self.stacks.lock().recycle(stack);
    }

    /// Recycles the given [`Stack`] for the register-machine `wasmi` engine backend.
    fn recycle_stack_2(&self, stack: Stack2) {
        self.stacks.lock().recycle_2(stack)
    }
}

/// Engine resources that are immutable during function execution.
///
/// Can be shared by multiple engine executors.
#[derive(Debug)]
pub struct EngineResources {
    /// Stores all Wasm function bodies that the interpreter is aware of.
    code_map: CodeMap,
    /// Stores information about all compiled functions.
    code_map_2: CodeMap2,
    /// A pool of reusable, deduplicated constant values.
    const_pool: ConstPool,
    /// Deduplicated function types.
    ///
    /// # Note
    ///
    /// The engine deduplicates function types to make the equality
    /// comparison very fast. This helps to speed up indirect calls.
    func_types: FuncTypeRegistry,
}

impl EngineResources {
    /// Creates a new [`EngineResources`].
    fn new() -> Self {
        let engine_idx = EngineIdx::new();
        Self {
            code_map: CodeMap::default(),
            code_map_2: CodeMap2::default(),
            const_pool: ConstPool::default(),
            func_types: FuncTypeRegistry::new(engine_idx),
        }
    }
}

/// The internal state of the `wasmi` engine.
#[derive(Debug)]
pub struct EngineExecutor<'engine> {
    /// Shared and reusable generic engine resources.
    res: &'engine EngineResources,
    /// The value and call stacks.
    stack: &'engine mut Stack,
}

impl<'engine> EngineExecutor<'engine> {
    /// Creates a new [`EngineExecutor`] with the given [`StackLimits`].
    fn new(res: &'engine EngineResources, stack: &'engine mut Stack) -> Self {
        Self { res, stack }
    }

    /// Executes the given [`Func`] using the given `params`.
    ///
    /// Stores the execution result into `results` upon a successful execution.
    ///
    /// # Errors
    ///
    /// - If the given `params` do not match the expected parameters of `func`.
    /// - If the given `results` do not match the the length of the expected results of `func`.
    /// - When encountering a Wasm or host trap during the execution of `func`.
    fn execute_func<T, Results>(
        &mut self,
        mut ctx: StoreContextMut<T>,
        func: &Func,
        params: impl CallParams,
        results: Results,
    ) -> Result<<Results as CallResults>::Results, TaggedTrap>
    where
        Results: CallResults,
    {
        self.stack.reset();
        self.stack.values.extend(params.call_params());
        match ctx.as_context().store.inner.resolve_func(func) {
            FuncEntity::Wasm(wasm_func) => {
                self.stack
                    .prepare_wasm_call(wasm_func, &self.res.code_map)?;
                self.execute_wasm_func(ctx.as_context_mut())?;
            }
            FuncEntity::Host(host_func) => {
                let host_func = *host_func;
                self.stack.call_host(
                    ctx.as_context_mut(),
                    host_func,
                    None,
                    &self.res.func_types,
                )?;
            }
        };
        let results = self.write_results_back(results);
        Ok(results)
    }

    /// Executes the given [`Func`] using the given `params`.
    ///
    /// Stores the execution result into `results` upon a successful execution.
    ///
    /// # Errors
    ///
    /// - If the given `params` do not match the expected parameters of `func`.
    /// - If the given `results` do not match the the length of the expected results of `func`.
    /// - When encountering a Wasm or host trap during the execution of `func`.
    fn execute_func_with_trace<T, Results>(
        &mut self,
        mut ctx: StoreContextMut<T>,
        func: &Func,
        params: impl CallParams,
        results: Results,
        tracer: Rc<RefCell<Tracer>>,
    ) -> Result<<Results as CallResults>::Results, TaggedTrap>
    where
        Results: CallResults,
    {
        self.stack.reset();
        self.stack.values.extend(params.clone().call_params());
        match ctx.as_context().store.inner.resolve_func(func) {
            FuncEntity::Wasm(wasm_func) => {
                self.stack
                    .prepare_wasm_call(wasm_func, &self.res.code_map)?;
                // Get initial values for MCC
                self.tracer_prepare_wasm_call(tracer.clone(), &self.stack.values.entries.to_vec());
                self.execute_wasm_func_with_trace(ctx.as_context_mut(), tracer)?;
            }
            FuncEntity::Host(..) => unimplemented!(),
        };
        let results = self.write_results_back(results);
        Ok(results)
    }

    fn tracer_prepare_wasm_call(
        &mut self,
        tracer: Rc<RefCell<Tracer>>,
        init_stack: &[UntypedValue],
    ) {
        let mut tracer = tracer.borrow_mut();
        tracer.set_IS_stack(init_stack);
    }

    /// Executes the given [`Func`] using the given `params`.
    ///
    /// Stores the execution result into `results` upon a successful execution.
    ///
    /// # Errors
    ///
    /// - If the given `params` do not match the expected parameters of `func`.
    /// - If the given `results` do not match the the length of the expected results of `func`.
    /// - When encountering a Wasm or host trap during the execution of `func`.
    fn execute_func_with_trace_v0<T, Results>(
        &mut self,
        mut ctx: StoreContextMut<T>,
        func: &Func,
        params: impl CallParams,
        results: Results,
        tracer: Rc<RefCell<TracerV0>>,
    ) -> Result<<Results as CallResults>::Results, TaggedTrap>
    where
        Results: CallResults,
    {
        self.stack.reset();
        let pre_sp = self
            .stack
            .values
            .stack_ptr()
            .offset_from(self.stack.values.base_ptr()) as usize;
        self.stack.values.extend(params.call_params());
        match ctx.as_context().store.inner.resolve_func(func) {
            FuncEntity::Wasm(wasm_func) => {
                self.stack
                    .prepare_wasm_call(wasm_func, &self.res.code_map)?;
                self.tracerv0_extend_stack(tracer.clone(), wasm_func, pre_sp);
                self.execute_wasm_func_with_trace_v0(ctx.as_context_mut(), tracer)?;
            }
            FuncEntity::Host(..) => unimplemented!(),
        };
        let results = self.write_results_back(results);
        Ok(results)
    }

    fn tracerv0_extend_stack(
        &mut self,
        tracer: Rc<RefCell<TracerV0>>,
        wasm_func: &WasmFuncEntity,
        pre_sp: usize,
    ) {
        let mut tracer = tracer.borrow_mut();
        let fn_header = self.res.code_map.header(wasm_func.func_body());
        let len_locals = fn_header.len_locals();

        tracer.push_len_locals(len_locals, pre_sp);
    }

    /// Resumes the execution of the given [`Func`] using `params`.
    ///
    /// Stores the execution result into `results` upon a successful execution.
    ///
    /// # Errors
    ///
    /// - If the given `params` do not match the expected parameters of `func`.
    /// - If the given `results` do not match the the length of the expected results of `func`.
    /// - When encountering a Wasm or host trap during the execution of `func`.
    fn resume_func<T, Results>(
        &mut self,
        mut ctx: StoreContextMut<T>,
        host_func: Func,
        params: impl CallParams,
        results: Results,
    ) -> Result<<Results as CallResults>::Results, TaggedTrap>
    where
        Results: CallResults,
    {
        self.stack
            .values
            .drop(host_func.ty(ctx.as_context()).params().len());
        self.stack.values.extend(params.call_params());
        assert!(
            self.stack.frames.peek().is_some(),
            "a frame must be on the call stack upon resumption"
        );
        self.execute_wasm_func(ctx.as_context_mut())?;
        let results = self.write_results_back(results);
        Ok(results)
    }

    /// Writes the results of the function execution back into the `results` buffer.
    ///
    /// # Note
    ///
    /// The value stack is empty after this operation.
    ///
    /// # Panics
    ///
    /// - If the `results` buffer length does not match the remaining amount of stack values.
    #[inline]
    fn write_results_back<Results>(&mut self, results: Results) -> <Results as CallResults>::Results
    where
        Results: CallResults,
    {
        results.call_results(self.stack.values.drain())
    }

    /// Executes the top most Wasm function on the [`Stack`] until the [`Stack`] is empty.
    ///
    /// # Errors
    ///
    /// When encountering a Wasm or host trap during the execution of `func`.
    #[inline(never)]
    fn execute_wasm_func<T>(&mut self, mut ctx: StoreContextMut<T>) -> Result<(), TaggedTrap> {
        let mut cache = self
            .stack
            .frames
            .peek()
            .map(FuncFrame::instance)
            .map(InstanceCache::from)
            .expect("must have frame on the call stack");
        loop {
            match self.execute_wasm(ctx.as_context_mut(), &mut cache)? {
                WasmOutcome::Return => return Ok(()),
                WasmOutcome::Call {
                    ref host_func,
                    instance,
                } => {
                    let func = host_func;
                    let host_func = match ctx.as_context().store.inner.resolve_func(func) {
                        FuncEntity::Wasm(_) => unreachable!("`func` must be a host function"),
                        FuncEntity::Host(host_func) => *host_func,
                    };
                    let result = self.stack.call_host(
                        ctx.as_context_mut(),
                        host_func,
                        Some(&instance),
                        &self.res.func_types,
                    );
                    if self.stack.frames.peek().is_some() {
                        // Case: There is a frame on the call stack.
                        //
                        // This is the default case and we can easily make host function
                        // errors return a resumable call handle.
                        result.map_err(|trap| TaggedTrap::host(*func, trap))?;
                    } else {
                        // Case: No frame is on the call stack. (edge case)
                        //
                        // This can happen if the host function was called by a tail call.
                        // In this case we treat host function errors the same as if we called
                        // the host function as root and do not allow to resume the call.
                        result.map_err(TaggedTrap::Wasm)?;
                    }
                }
            }
        }
    }

    /// Executes the top most Wasm function on the [`Stack`] until the [`Stack`] is empty.
    ///
    /// # Errors
    ///
    /// When encountering a Wasm or host trap during the execution of `func`.
    #[inline(never)]
    fn execute_wasm_func_with_trace<T>(
        &mut self,
        mut ctx: StoreContextMut<T>,
        tracer: Rc<RefCell<Tracer>>,
    ) -> Result<(), TaggedTrap> {
        let mut cache = self
            .stack
            .frames
            .peek()
            .map(FuncFrame::instance)
            .map(InstanceCache::from)
            .expect("must have frame on the call stack");
        loop {
            match self.execute_wasm_with_trace(ctx.as_context_mut(), &mut cache, tracer.clone())? {
                WasmOutcome::Return => return Ok(()),
                WasmOutcome::Call {
                    ref host_func,
                    instance,
                } => {
                    let func = host_func;
                    let host_func = match ctx.as_context().store.inner.resolve_func(func) {
                        FuncEntity::Wasm(_) => unreachable!("`func` must be a host function"),
                        FuncEntity::Host(host_func) => *host_func,
                    };
                    let result = self.stack.call_host_with_trace(
                        ctx.as_context_mut(),
                        host_func,
                        Some(&instance),
                        &self.res.func_types,
                        tracer.clone(),
                    );
                    if self.stack.frames.peek().is_some() {
                        // Case: There is a frame on the call stack.
                        //
                        // This is the default case and we can easily make host function
                        // errors return a resumable call handle.
                        result.map_err(|trap| TaggedTrap::host(*func, trap))?;
                    } else {
                        // Case: No frame is on the call stack. (edge case)
                        //
                        // This can happen if the host function was called by a tail call.
                        // In this case we treat host function errors the same as if we called
                        // the host function as root and do not allow to resume the call.
                        result.map_err(TaggedTrap::Wasm)?;
                    }
                }
            }
        }
    }

    /// Executes the top most Wasm function on the [`Stack`] until the [`Stack`] is empty.
    ///
    /// # Errors
    ///
    /// When encountering a Wasm or host trap during the execution of `func`.
    #[inline(never)]
    fn execute_wasm_func_with_trace_v0<T>(
        &mut self,
        mut ctx: StoreContextMut<T>,
        tracer: Rc<RefCell<TracerV0>>,
    ) -> Result<(), TaggedTrap> {
        let mut cache = self
            .stack
            .frames
            .peek()
            .map(FuncFrame::instance)
            .map(InstanceCache::from)
            .expect("must have frame on the call stack");
        loop {
            match self.execute_wasm_with_trace_v0(
                ctx.as_context_mut(),
                &mut cache,
                tracer.clone(),
            )? {
                WasmOutcome::Return => return Ok(()),
                WasmOutcome::Call {
                    ref host_func,
                    instance,
                } => {
                    let func = host_func;
                    let host_func = match ctx.as_context().store.inner.resolve_func(func) {
                        FuncEntity::Wasm(_) => unreachable!("`func` must be a host function"),
                        FuncEntity::Host(host_func) => *host_func,
                    };
                    let result = self.stack.call_host_with_trace_v0(
                        ctx.as_context_mut(),
                        host_func,
                        Some(&instance),
                        &self.res.func_types,
                        tracer.clone(),
                    );

                    if self.stack.frames.peek().is_some() {
                        // Case: There is a frame on the call stack.
                        //
                        // This is the default case and we can easily make host function
                        // errors return a resumable call handle.
                        result.map_err(|trap| TaggedTrap::host(*func, trap))?;
                    } else {
                        // Case: No frame is on the call stack. (edge case)
                        //
                        // This can happen if the host function was called by a tail call.
                        // In this case we treat host function errors the same as if we called
                        // the host function as root and do not allow to resume the call.
                        result.map_err(TaggedTrap::Wasm)?;
                    }
                }
            }
        }
    }

    /// Executes the given function `frame`.
    ///
    /// # Note
    ///
    /// This executes Wasm instructions until either the execution calls
    /// into a host function or the Wasm execution has come to an end.
    ///
    /// # Errors
    ///
    /// If the Wasm execution traps.
    #[inline(always)]
    fn execute_wasm<T>(
        &mut self,
        ctx: StoreContextMut<T>,
        cache: &mut InstanceCache,
    ) -> Result<WasmOutcome, Trap> {
        /// Converts a [`TrapCode`] into a [`Trap`].
        ///
        /// This function exists for performance reasons since its `#[cold]`
        /// annotation has severe effects on performance.
        #[inline]
        #[cold]
        fn make_trap(code: TrapCode) -> Trap {
            code.into()
        }

        let (store_inner, mut resource_limiter) = ctx.store.store_inner_and_resource_limiter_ref();
        let value_stack = &mut self.stack.values;
        let call_stack = &mut self.stack.frames;
        let code_map = &self.res.code_map;
        let const_pool = self.res.const_pool.view();

        execute_wasm(
            store_inner,
            cache,
            value_stack,
            call_stack,
            code_map,
            const_pool,
            &mut resource_limiter,
        )
        .map_err(make_trap)
    }

    /// Executes the given function `frame`.
    ///
    /// # Note
    ///
    /// This executes Wasm instructions until either the execution calls
    /// into a host function or the Wasm execution has come to an end.
    ///
    /// # Errors
    ///
    /// If the Wasm execution traps.
    #[inline(always)]
    fn execute_wasm_with_trace<T>(
        &mut self,
        ctx: StoreContextMut<T>,
        cache: &mut InstanceCache,
        tracer: Rc<RefCell<Tracer>>,
    ) -> Result<WasmOutcome, Trap> {
        /// Converts a [`TrapCode`] into a [`Trap`].
        ///
        /// This function exists for performance reasons since its `#[cold]`
        /// annotation has severe effects on performance.
        #[inline]
        #[cold]
        fn make_trap(code: TrapCode) -> Trap {
            code.into()
        }

        let (store_inner, mut resource_limiter) = ctx.store.store_inner_and_resource_limiter_ref();
        let value_stack = &mut self.stack.values;
        let call_stack = &mut self.stack.frames;
        let code_map = &self.res.code_map;
        let const_pool = self.res.const_pool.view();

        execute_wasm_with_trace(
            store_inner,
            cache,
            value_stack,
            call_stack,
            code_map,
            const_pool,
            &mut resource_limiter,
            tracer,
        )
        .map_err(make_trap)
    }

    /// Executes the given function `frame`.
    ///
    /// # Note
    ///
    /// This executes Wasm instructions until either the execution calls
    /// into a host function or the Wasm execution has come to an end.
    ///
    /// # Errors
    ///
    /// If the Wasm execution traps.
    #[inline(always)]
    fn execute_wasm_with_trace_v0<T>(
        &mut self,
        ctx: StoreContextMut<T>,
        cache: &mut InstanceCache,
        tracer: Rc<RefCell<TracerV0>>,
    ) -> Result<WasmOutcome, Trap> {
        /// Converts a [`TrapCode`] into a [`Trap`].
        ///
        /// This function exists for performance reasons since its `#[cold]`
        /// annotation has severe effects on performance.
        #[inline]
        #[cold]
        fn make_trap(code: TrapCode) -> Trap {
            code.into()
        }

        let (store_inner, mut resource_limiter) = ctx.store.store_inner_and_resource_limiter_ref();
        let value_stack = &mut self.stack.values;
        let call_stack = &mut self.stack.frames;
        let code_map = &self.res.code_map;
        let const_pool = self.res.const_pool.view();

        execute_wasm_with_trace_v0(
            store_inner,
            cache,
            value_stack,
            call_stack,
            code_map,
            const_pool,
            &mut resource_limiter,
            tracer,
        )
        .map_err(make_trap)
    }
}
