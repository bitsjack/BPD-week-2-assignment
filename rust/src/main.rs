//#![allow(unused)]
use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::key::Secp256k1;
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::secp256k1::{Message, SecretKey};
use bitcoin::sighash::SighashCache;
use bitcoin::transaction::{OutPoint, Transaction, TxIn, TxOut, Version};
use bitcoin::{Address, Amount, EcdsaSighashType, Network, ScriptBuf, Sequence, Txid, Witness};
use std::fs::File;
use std::io::Write;
use std::str::FromStr;

/// Find the starting index of `needle` inside `haystack`, if present.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    //configuration & constants
    let private_key_1_hex = "39dc0a9f0b185a2ee56349691f34716e6e0cda06a7f9707742ac113c4e2317bf";
    let private_key_2_hex = "5077ccd9c558b7d04a81920d38aa11b4a9f9de3b23fab45c3ef28039920fdd6d";
    let redeem_script_hex = "5221032ff8c5df0bc00fe1ac2319c3b8070d6d1e04cfbf4fedda499ae7b775185ad53b21039bbc8d24f89e5bc44c5b0d1980d6658316a6b2440023117c3c03a4975b04dd5652ae";
    let redeem_script = ScriptBuf::from_hex(redeem_script_hex)?;

    let secp = Secp256k1::new();
    let private_key_1 = SecretKey::from_str(private_key_1_hex).expect("valid priv key 1");
    let private_key_2 = SecretKey::from_str(private_key_2_hex).expect("valid priv key 2");

    // Recover the compressed pubkeys and sanity check they match the redeem script.
    let pk1 = bitcoin::PublicKey::new(private_key_1.public_key(&secp));
    let pk2 = bitcoin::PublicKey::new(private_key_2.public_key(&secp));
    println!("pubkey1: {}", pk1);
    println!("pubkey2: {}", pk2);

    //create witness script  (== redeem script) hash for P2WSH
    let witness_script = redeem_script.clone();
    let wsh = witness_script.wscript_hash();

    // P2WSH witness program script: OP_0 <32-byte-hash>
    let witness_program_script = ScriptBuf::new_p2wsh(&wsh);

    // The P2SH scriptPubKey wraps the witness program script (its hash160)
    let script_pubkey = ScriptBuf::new_p2sh(&witness_program_script.script_hash());

    // Confirm this matches the expected P2SH address
    let derived_addr = Address::p2sh(&witness_program_script, Network::Bitcoin).unwrap();
    println!("Derived P2SH address (input): {}", derived_addr);

    //output address & amount
    let value = Amount::from_sat(100000);
    let dest_address = Address::from_str("325UUecEQuyrTd28Xs2hvAxdAjHM7XzqVF")
        .unwrap()
        .require_network(Network::Bitcoin)
        .expect("mainnet address");
    let dest_script = dest_address.script_pubkey();

    //safely convert to PushBytesBuf using standard error handling
    let push_bytes = PushBytesBuf::try_from(witness_program_script.into_bytes())
        .map_err(|_| "Redeem script exceeds maximum push size limit")?;

    //script sig containing only P2SH redeem script push
    let script_sig = Builder::new().push_slice(push_bytes).into_script();

    //creating transaction
    let outpoint = OutPoint {
        txid: Txid::from_byte_array([0u8; 32]),
        vout: 0,
    };

    let tx_in = TxIn {
        previous_output: outpoint,
        script_sig,
        sequence: Sequence(0xffffffff),
        witness: Witness::new(),
    };

    let tx_out = TxOut {
        value: value,
        script_pubkey: dest_script,
    };

    let mut create_tx = Transaction {
        version: Version::non_standard(2),
        lock_time: LockTime::ZERO,
        input: vec![tx_in],
        output: vec![tx_out],
    };

    //Calculate sighash for P2WSH spend
    let input_value = value;
    let sighash_type = EcdsaSighashType::All;
    let sighash = SighashCache::new(&create_tx)
        .p2wsh_signature_hash(0, &redeem_script, input_value, sighash_type)
        .expect("Failed to compute sighash");

    let msg = Message::from_digest_slice(sighash.as_byte_array()).expect("32 bytes message");

    //sign with both private keys
    let sig1 = secp.sign_ecdsa(&msg, &private_key_1);
    let sig2 = secp.sign_ecdsa(&msg, &private_key_2);

    // Verify locally before using them
    secp.verify_ecdsa(&msg, &sig1, &pk1.inner)
        .expect("sig1 valid");
    secp.verify_ecdsa(&msg, &sig2, &pk2.inner)
        .expect("sig2 valid");

    let mut sig1_der = sig1.serialize_der().to_vec();
    sig1_der.push(sighash_type.to_u32() as u8);
    let mut sig2_der = sig2.serialize_der().to_vec();
    sig2_der.push(sighash_type.to_u32() as u8);

    println!(
        "Signature 1 (DER+sighash, priv1): {}",
        hex::encode(&sig1_der)
    );
    println!(
        "Signature 2 (DER+sighash, priv2): {}",
        hex::encode(&sig2_der)
    );

    //determine the correct signature order
    let redeem_script_bytes = redeem_script.as_bytes();
    let pos1 = find_subslice(redeem_script_bytes, pk1.inner.serialize().as_slice())
        .expect("pubkey1 must be present in redeem script");
    let pos2 = find_subslice(redeem_script_bytes, pk2.inner.serialize().as_slice())
        .expect("pubkey2 must be present in redeem script");
    println!("pubkey1 (priv1) offset in redeem script: {}", pos1);
    println!("pubkey2 (priv2) offset in redeem script: {}", pos2);

    let (first_sig, second_sig) = if pos1 < pos2 {
        (sig1_der, sig2_der)
    } else {
        (sig2_der, sig1_der)
    };

    //assembly witness stack
    let mut witness = Witness::new();
    witness.push(vec![]);
    witness.push(first_sig);
    witness.push(second_sig);
    witness.push(redeem_script.to_bytes());

    create_tx.input[0].witness = witness;

    //write transaction hex to out.txt
    let tx_hex = bitcoin::consensus::encode::serialize_hex(&create_tx);
    let mut file = File::create("out.txt")?;
    writeln!(file, "{}", tx_hex)?;
    println!("Transaction hex successfully written to out.txt");

    // sanity check: expected scriptPubKey should equal derived address's script
    assert_eq!(script_pubkey, derived_addr.script_pubkey());
    println!(
        "scriptPubKey (for reference, not part of tx): {}",
        script_pubkey
    );
    Ok(())
}
