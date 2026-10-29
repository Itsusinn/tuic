use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use rustls::sign::CertifiedKey as RustlsCertifiedKey;

/// A `localhost` leaf certificate signed by a freshly generated CA, plus the CA
/// PEM that `[tls] certificates` would hold.
pub struct SignedServer {
	pub ca_pem: String,
	pub leaf: RustlsCertifiedKey,
}

/// Build the CA + leaf pair.
///
/// The extra CA step (instead of a self-signed leaf) mirrors how a private
/// relay is deployed and exercises real chain building rather than the
/// trust-store "leaf is its own anchor" special case.
pub fn signed_server_cert(name: &str) -> SignedServer {
	let provider = rustls::crypto::CryptoProvider::get_default().expect("crypto provider must be installed first");

	let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
	ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
	ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
	let ca_key = KeyPair::generate().expect("ca key");
	let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");
	let issuer = Issuer::new(ca_params, &ca_key);

	let leaf_params = CertificateParams::new(vec![name.to_string()]).expect("leaf params");
	let leaf_key = KeyPair::generate().expect("leaf key");
	let leaf_cert = leaf_params.signed_by(&leaf_key, &issuer).expect("sign leaf");

	let signing_key = provider
		.key_provider
		.load_private_key(rustls::pki_types::PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into()))
		.expect("leaf private key must be supported by the provider");
	let leaf = RustlsCertifiedKey::new(vec![leaf_cert.der().clone()], signing_key);
	SignedServer {
		ca_pem: ca_cert.pem(),
		leaf,
	}
}
