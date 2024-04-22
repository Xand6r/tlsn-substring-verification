use std::str;
use std::time::Duration;

use elliptic_curve::pkcs8::DecodePublicKey;
use tlsn_core::{
    merkle::MerkleProof,
    proof::{SessionProof, TlsProof},
};
use types::{convert_hashmap_from_std_to_brown, PublicSubstringsProof};

// use the no_std lib

use crate::types::{CustomHashMap, GuestSubstringsProof, OpeningsHashMap};
use tlsn_substrings_verifier::proof::{SessionHeader, SubstringsProof as ParameterSubstringsProof};

pub mod types;

fn main() {
    // Deserialize the proof
    let proof = std::fs::read_to_string("fixtures/proof.json").unwrap();
    let proof: TlsProof = serde_json::from_str(proof.as_str()).unwrap();

    let TlsProof {
        // The session proof establishes the identity of the server and the commitments
        // to the TLS transcript.
        session,
        // The substrings proof proves select portions of the transcript, while redacting
        // anything the Prover chose not to disclose.
        substrings,
    } = proof;

    // Verify the session proof against the Notary's public key
    //
    // This verifies the identity of the server using a default certificate verifier which trusts
    // the root certificates from the `webpki-roots` crate.
    session
        .verify_with_default_cert_verifier(notary_pubkey())
        .unwrap();

    let SessionProof {
        // The session header that was signed by the Notary is a succinct commitment to the TLS transcript.
        header,
        // This is the server name, checked against the certificate chain shared in the TLS handshake.
        server_name,
        ..
    } = session;

    // The time at which the session was recorded
    let time = chrono::DateTime::UNIX_EPOCH + Duration::from_secs(header.time());

    // type conversion occurs here
    // it appears to serialise the object we need to convert it into the expected format
    let serialized_substring = serde_json::to_string(&substrings).expect("Serialization failed");
    let public_substring: PublicSubstringsProof =
        serde_json::from_str(&serialized_substring).expect("DeSerialization failed");

    let parsed_inclusion_proof: MerkleProof =
        serde_json::from_str(&serde_json::to_string(&public_substring.inclusion_proof).unwrap())
            .expect("Deserialization failed");

    // we would need to convert from std hashmap to brown hashmap

    let parsed_openings: OpeningsHashMap =
        convert_hashmap_from_std_to_brown(public_substring.openings);

    let parsed_openings = CustomHashMap(parsed_openings);
    // construct the original array back
    let guest_formatted_prooof = GuestSubstringsProof {
        openings: parsed_openings,
        inclusion_proof: parsed_inclusion_proof,
    };

    // todo execute this part in the zk circuit
    // todo serialise the header and then pass it into the guest code
    // reconstruct the substrings struct and provide the header
    // substrings
    let serialized = serde_json::to_string(&guest_formatted_prooof).expect("Serialization failed");
    let reconstructed_substring: ParameterSubstringsProof =
        serde_json::from_str(&serialized).expect("Deserialization failed");

    let reconstructed_header: SessionHeader =
        serde_json::from_str(&serde_json::to_string(&header).unwrap())
            .expect("Deserialization failed");

    // pass the serialized header to the zkaf function which would just reconstruct it from the respective serialized strings
    // ====== reconstruct substrings by passing it to the ZK
    // ====== pass header
    // let (mut sent, mut recv) = substrings.verify(&header).unwrap();

    // todo serialise the header and then pass it into the guest code
    // todo execute this part in the zk circuit
    // logic to call the circuit is mentioned here
    // so the zk logic to call the elf package would be here
    let (mut sent, mut recv) = reconstructed_substring.verify(&reconstructed_header).unwrap();
    // reconstruct the header too, just serialize and deserialize

    println!("{:?}", recv);
    // println!("Hello, world!");
}

/// Returns a Notary pubkey trusted by this Verifier
fn notary_pubkey() -> p256::PublicKey {
    let pem_file = str::from_utf8(include_bytes!("../fixtures/notary.pub")).unwrap();
    p256::PublicKey::from_public_key_pem(pem_file).unwrap()
}
