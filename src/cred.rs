use std::any::Any;
use std::collections::HashMap;
use std::fmt::Formatter;
use std::sync::Arc;

use zeroize::Zeroize;

use keyring_core::api::CredentialApi;
use keyring_core::attributes::parse_attributes;
use keyring_core::{Credential, Error as ErrorCode, Result};

pub use crate::utils::CredPersist;
use crate::utils::{
    delete_credential, extract_attributes, extract_from_credential, extract_password,
    extract_secret, save_credential, validate_attributes, validate_password, validate_secret,
    validate_target,
};

/// Cred specifies or wraps a generic credential.
/// Whether it's a specifier or wrapper depends on the specifiers field,
/// which is a tuple <service, user> or `None`.
#[derive(Debug, Clone)]
pub(crate) struct Cred {
    pub target_name: String,
    pub specifiers: Option<(String, String)>,
    pub persistence: CredPersist,
    pub require_biometric: bool,
}

impl Cred {
    /// Create a Windows generic credential from the given specifiers.
    ///
    /// An explicit target string is interpreted as the target to use for the entry.
    /// If none is provided, then we concatenate the user and service in the string
    /// `{delimiters[0]}{user}{delimiters[1]}{service}{delimiters[2]}`.
    pub fn build_from_specifiers(
        target: Option<&str>,
        delimiters: &[String; 3],
        service_no_dividers: bool,
        service: &str,
        user: &str,
        persistence: CredPersist,
        require_biometric: bool,
    ) -> Result<Self> {
        let (target_name, specifiers) = match target {
            Some(value) => (value.to_string(), None),
            None => {
                if service_no_dividers && service.contains(delimiters[1].as_str()) {
                    return Err(ErrorCode::Invalid(
                        "service".to_string(),
                        "cannot contain delimiter".to_string(),
                    ));
                }
                (
                    format!(
                        "{}{user}{}{service}{}",
                        delimiters[0], delimiters[1], delimiters[2]
                    ),
                    Some((service.to_string(), user.to_string())),
                )
            }
        };
        validate_target(
            &target_name,
            &specifiers
                .as_ref()
                .map_or_else(String::new, |s| s.1.clone()),
        )?;
        Ok(Self {
            target_name,
            specifiers,
            persistence,
            require_biometric,
        })
    }

    /// Verify biometric identity if required for this credential.
    /// When the `biometric` feature is not enabled and biometric is required,
    /// this returns an error indicating the feature is not available.
    fn verify_biometric_if_required(&self) -> Result<()> {
        if !self.require_biometric {
            return Ok(());
        }
        #[cfg(feature = "biometric")]
        {
            let message = if let Some((service, user)) = &self.specifiers {
                format!("Authenticate to access credential for '{user}' on '{service}'")
            } else {
                format!("Authenticate to access credential '{}'", self.target_name)
            };
            crate::biometric::verify_user(&message)
        }
        #[cfg(not(feature = "biometric"))]
        {
            Err(ErrorCode::NoStorageAccess(Box::new(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "biometric feature is not enabled",
            ))))
        }
    }
}

impl CredentialApi for Cred {
    /// See the keyring-core API docs.
    ///
    // Password strings are converted to UTF-16 because that's the native
    // charset for Windows strings.  This allows interoperability with native
    // Windows credential APIs.  But the storage for the credential is actually
    // a little-endian blob, because Windows credentials can contain anything.
    fn set_password(&self, password: &str) -> Result<()> {
        self.verify_biometric_if_required()?;
        let mut secret = validate_password(password)?;
        let result = self.set_secret_internal(&secret);
        // make sure that the copy of the secret is erased
        secret.zeroize();
        result
    }

    /// See the keyring-core API docs.
    fn set_secret(&self, secret: &[u8]) -> Result<()> {
        self.verify_biometric_if_required()?;
        self.set_secret_internal(secret)
    }

    /// See the keyring-core API docs.
    fn get_password(&self) -> Result<String> {
        self.verify_biometric_if_required()?;
        extract_from_credential(&self.target_name, extract_password)
    }

    /// See the keyring-core API docs.
    fn get_secret(&self) -> Result<Vec<u8>> {
        self.verify_biometric_if_required()?;
        extract_from_credential(&self.target_name, extract_secret)
    }

    /// See the keyring-core API docs.
    fn get_attributes(&self) -> Result<HashMap<String, String>> {
        extract_from_credential(&self.target_name, extract_attributes)
    }

    /// See the keyring-core API docs.
    fn update_attributes(&self, attributes: &HashMap<&str, &str>) -> Result<()> {
        let new = parse_attributes(&["username", "target_alias", "comment"], Some(attributes))?;
        let old = self.get_attributes()?;
        let username = new
            .get("username")
            .cloned()
            .unwrap_or_else(|| old["username"].clone());
        let target_alias = new
            .get("target_alias")
            .cloned()
            .unwrap_or_else(|| old["target_alias"].clone());
        let comment = new
            .get("comment")
            .cloned()
            .unwrap_or_else(|| old["comment"].clone());
        validate_attributes(&username, &target_alias, &comment)?;
        let mut secret = self.get_secret()?;
        let result = save_credential(
            &self.target_name,
            &username,
            &target_alias,
            &comment,
            &secret,
            &self.persistence,
        );
        // erase the copy of the secret
        secret.zeroize();
        result
    }

    /// See the keyring-core API docs.
    fn delete_credential(&self) -> Result<()> {
        self.verify_biometric_if_required()?;
        delete_credential(&self.target_name)
    }

    /// See the keyring-core API docs.
    ///
    /// No ambiguity, so every wrap is its own wrapper
    fn get_credential(&self) -> Result<Option<Arc<Credential>>> {
        let persistence: CredPersist = self.get_attributes()?["persistence"].parse()?;
        if self.persistence == persistence {
            Ok(None)
        } else {
            let mut new = self.clone();
            new.persistence = persistence;
            Ok(Some(Arc::new(new)))
        }
    }

    /// See the keyring-core API docs.
    fn get_specifiers(&self) -> Option<(String, String)> {
        self.specifiers.clone()
    }

    /// See the keyring-core API docs.
    fn as_any(&self) -> &dyn Any {
        self
    }

    /// See the keyring-core API docs.
    fn debug_fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl Cred {
    /// Internal set_secret that bypasses the biometric check.
    /// Called by set_password (which already verified biometric) and set_secret.
    fn set_secret_internal(&self, secret: &[u8]) -> Result<()> {
        validate_secret(secret)?;
        let mut username = if let Some((_, user)) = &self.specifiers {
            user.to_owned()
        } else {
            String::new()
        };
        let mut target_alias = String::new();
        let mut comment = String::new();
        if let Ok(attributes) = self.get_attributes() {
            username = attributes["username"].clone();
            target_alias = attributes["target_alias"].clone();
            comment = attributes["comment"].clone();
        }
        save_credential(
            &self.target_name,
            &username,
            &target_alias,
            &comment,
            secret,
            &self.persistence,
        )
    }
}
