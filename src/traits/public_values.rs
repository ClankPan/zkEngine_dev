//! Contains the required methods needed from the public values for the ZKVM proving with
//! (Super)Nova.
use nova::traits::CurveCycleEquipped;

/// Define public values for a (Super)Nova proving system.
pub trait PublicValuesTrait<E1: CurveCycleEquipped> {
  /// Getter for the public inputs of the proving system (z0)
  fn public_inputs(&self) -> &[E1::Scalar];

  /// Getter for the public outputs of the proving system (zi)
  fn public_outputs(&self) -> &[E1::Scalar];
}

/// Define public values for a ZKVM proving system.
pub trait ZKVMPublicValues<E1: CurveCycleEquipped> {
  /// Public values for MCC
  type MCCPublicValues: PublicValuesTrait<E1>;

  /// Public values for execution proving
  type ExecutionPublicValues: PublicValuesTrait<E1>;

  /// Getter for the public values of MCC
  fn mcc(&self) -> &Self::MCCPublicValues;

  /// Getter for the public values of execution proving
  fn execution(&self) -> &Self::ExecutionPublicValues;
}
