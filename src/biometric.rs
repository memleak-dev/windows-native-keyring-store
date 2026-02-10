use windows::Security::Credentials::UI::{
    UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
};

use keyring_core::error::{Error, Result};

/// Errors specific to biometric verification via Windows Hello.
#[derive(Debug)]
pub enum BiometricError {
    DeviceNotPresent,
    NotConfigured,
    DisabledByPolicy,
    DeviceBusy,
    RetriesExhausted,
    Canceled,
    Unknown,
}

impl std::fmt::Display for BiometricError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DeviceNotPresent => write!(f, "Windows Hello device not present"),
            Self::NotConfigured => write!(f, "Windows Hello not configured for user"),
            Self::DisabledByPolicy => write!(f, "Windows Hello disabled by policy"),
            Self::DeviceBusy => write!(f, "Windows Hello device busy"),
            Self::RetriesExhausted => write!(f, "Windows Hello retries exhausted"),
            Self::Canceled => write!(f, "Windows Hello verification canceled by user"),
            Self::Unknown => write!(f, "Unknown Windows Hello error"),
        }
    }
}

impl std::error::Error for BiometricError {}

/// Check if Windows Hello biometric verification is available on this device.
pub fn is_available() -> bool {
    let op = match UserConsentVerifier::CheckAvailabilityAsync() {
        Ok(op) => op,
        Err(_) => return false,
    };
    match op.get() {
        Ok(availability) => availability == UserConsentVerifierAvailability::Available,
        Err(_) => false,
    }
}

/// Prompt the user for biometric verification via Windows Hello.
///
/// This presents a system dialog asking the user to verify their identity
/// using fingerprint, face recognition, or PIN (depending on device capabilities).
pub fn verify_user(message: &str) -> Result<()> {
    let op = UserConsentVerifier::RequestVerificationAsync(&message.into())
        .map_err(|e| Error::PlatformFailure(Box::new(e)))?;

    let result = op.get().map_err(|e| Error::PlatformFailure(Box::new(e)))?;

    match result {
        UserConsentVerificationResult::Verified => Ok(()),
        UserConsentVerificationResult::DeviceNotPresent => Err(Error::NoStorageAccess(
            Box::new(BiometricError::DeviceNotPresent),
        )),
        UserConsentVerificationResult::NotConfiguredForUser => Err(Error::NoStorageAccess(
            Box::new(BiometricError::NotConfigured),
        )),
        UserConsentVerificationResult::DisabledByPolicy => Err(Error::NoStorageAccess(
            Box::new(BiometricError::DisabledByPolicy),
        )),
        UserConsentVerificationResult::DeviceBusy => {
            Err(Error::NoStorageAccess(Box::new(BiometricError::DeviceBusy)))
        }
        UserConsentVerificationResult::RetriesExhausted => Err(Error::NoStorageAccess(
            Box::new(BiometricError::RetriesExhausted),
        )),
        UserConsentVerificationResult::Canceled => {
            Err(Error::NoStorageAccess(Box::new(BiometricError::Canceled)))
        }
        _ => Err(Error::NoStorageAccess(Box::new(BiometricError::Unknown))),
    }
}
