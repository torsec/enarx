// SPDX-License-Identifier: Apache-2.0

//! The Enarx Wasm runtime and all related functionality

mod identity;
mod io;
mod net;

use crate::runtime::identity::pki::PrivateKeyInfoExt;
use crate::runtime::identity::platform::{Platform, Technology};

use self::io::null::Null;
use self::io::stdio_file;
use self::net::{connect_file, listen_file};

use super::{Package, Workload};

use anyhow::Context;
use enarx_config::{Config, File};
use pkcs8::der::Decode;
use pkcs8::PrivateKeyInfo;
use sha2::digest::generic_array::GenericArray;
use sha2::{Digest, Sha256, Sha384};
use wasi_common::file::FileCaps;
use wasi_common::WasiFile;
use wasmtime::{AsContextMut, Engine, Linker, Module, Store, Val};
use wasmtime_wasi::stdio::{stderr, stdin, stdout};
use wasmtime_wasi::{add_to_linker, WasiCtxBuilder};
use wiggle::tracing::{instrument, trace_span};

// The Enarx Wasm runtime
pub struct Runtime;

impl Runtime {
    // Execute an Enarx [Package]
    #[instrument]
    pub fn execute(package: Package) -> anyhow::Result<Vec<Val>> {
        let (prvkey, crtreq) =
            identity::generate().context("failed to generate a private key and CSR")?;

        let Workload { webasm, config } = package.try_into()?;
        let Config {
            steward,
            tm,
            args,
            files,
            env,
        } = config.unwrap_or_default();

        let cert_chain = if let Some(url) = steward {
            identity::steward(&url, crtreq.clone()).context("failed to attest to Steward")?
        } else {
            identity::selfsigned(&prvkey).context("failed to generate self-signed certificates")?
        };

        let certs = cert_chain.clone()
            .into_iter()
            .map(rustls::Certificate)
            .collect::<Vec<_>>();

        /*** Thesis TM Integration - JC ***/

        // Get the Trust Monitor URL
        let tm_url = tm.expect("TM URL must be defined inside Enarx.toml");
        println!("\nTM URL contacted: {}", tm_url.as_str());

        // Get the PKI from the generated keypair in byte format
        let pki = PrivateKeyInfo::from_der(&prvkey)
            .context("failed to parse DER-encoded private key before sign the wasm")?;

        // Get the algorithm used to generate the PKI
        let sign_algo = pki.signs_with()?;
        // println!("Key Algorithm: {:?}", sign_algo.oid);

        // Digest sha256 of the wasm file
        let platform = Platform::get().context("failed to query platform")?;

        let mut hash_256 = GenericArray::default();
        let mut hash_384 = GenericArray::default();
        match platform.technology() {
            Technology::Snp => {
                hash_384 = Sha384::digest(&webasm);
                println!("SHA384(wasm): {:x}", hash_384);
            }
            _ => {
                hash_256 = Sha256::digest(&webasm);
                println!("SHA256(wasm): {:x}", hash_256);
            }
        };

        // Sign the .wasm with the PKI
        let signed_hashed_wasm = pki.sign(&webasm, sign_algo)
            .context("failed to sign the hash of the wasm file")?;

        // Print the signature over the .wasm with ECDSA_P256_SHA256_ASN1_SIGNING | ECDSA_P384_SHA384_ASN1_SIGNING
        println!("Size signature on digest(wasm): {}", signed_hashed_wasm.len());
        print!("\nSignature on digest(wasm): ");
        for byte in signed_hashed_wasm.iter() {
            print!("{:02x}", byte);
        }
        print!("\n");

        // Create aggregated data bytes to send to the TM:
        // agg_data:Vec<u8> {
        //      hash_dimension: byte
        //      size_signature: byte
        //      hash_of_wasm: bytes
        //      signature: bytes
        //      certificate_emitted_by_Steward: bytes
        //}

        let mut agg_data = Vec::new();

        //Add the hash dimension
        match platform.technology() {
            Technology::Snp => {
                agg_data.push(48);
            }
            _ => {
                agg_data.push(32);
            }
        };

        // Add the size_signature
        agg_data.push(signed_hashed_wasm.len().try_into()
                        .context("failed to convert form usize to u8")?);

        //Add the hash of the wasm
        match platform.technology() {
            Technology::Snp => {
                agg_data.extend_from_slice(&hash_384);
            }
            _ => {
                agg_data.extend_from_slice(&hash_256);
            }
        };
        
        // Add the signature
        agg_data.extend_from_slice(&signed_hashed_wasm);
        // println!("\n{:?}", agg_data.len());

        // Add the certificate of the Keep released by the Steward
        agg_data.extend_from_slice(&cert_chain[0]);
        // println!("{:?}", agg_data);

        let response_tm = identity::trust_monitor(&tm_url, agg_data)
            .context("failed to attest signature of wasm to Trust Monitor")?;
        
        println!("{}\n", response_tm);

        /**************************************/

        let mut config = wasmtime::Config::new();
        config.memory_init_cow(false);
        let engine = trace_span!("initialize Wasmtime engine")
            .in_scope(|| Engine::new(&config))
            .context("failed to create execution engine")?;

        let mut linker = trace_span!("setup linker").in_scope(|| Linker::new(&engine));
        trace_span!("link WASI")
            .in_scope(|| add_to_linker(&mut linker, |s| s))
            .context("failed to setup linker and link WASI")?;

        let mut wstore = trace_span!("initialize Wasmtime store")
            .in_scope(|| Store::new(&engine, WasiCtxBuilder::new().build()));

        let module = trace_span!("compile Wasm")
            .in_scope(|| Module::from_binary(&engine, &webasm))
            .context("failed to compile Wasm module")?;
        trace_span!("link Wasm")
            .in_scope(|| linker.module(&mut wstore, "", &module))
            .context("failed to link module")?;

        let mut ctx = wstore.as_context_mut();
        let ctx = ctx.data_mut();

        let mut names = vec![];
        for (fd, file) in files.iter().enumerate() {
            names.push(file.name());
            let (file, caps): (Box<dyn WasiFile>, _) = match file {
                File::Null(..) => (Box::new(Null), FileCaps::all()),
                File::Stdin(..) => stdio_file(stdin()),
                File::Stdout(..) => stdio_file(stdout()),
                File::Stderr(..) => stdio_file(stderr()),
                File::Listen(file) => listen_file(file, certs.clone(), &prvkey)
                    .context("failed to setup listening socket")?,
                File::Connect(file) => connect_file(file, certs.clone(), &prvkey)
                    .context("failed to setup connection stream")?,
            };
            let fd = fd.try_into().context("too many open files")?;
            ctx.insert_file(fd, file, caps);
        }
        ctx.push_env("FD_COUNT", &names.len().to_string())
            .context("failed to set environment variable `FD_COUNT`")?;
        ctx.push_env("FD_NAMES", &names.join(":"))
            .context("failed to set environment variable `FD_NAMES`")?;

        for (k, v) in env {
            ctx.push_env(&k, &v)
                .context("failed to set environment variable `{k}`")?;
        }

        ctx.push_arg("main.wasm")
            .context("failed to push argv[0]")?;
        for arg in args {
            ctx.push_arg(&arg).context("failed to push argument")?;
        }

        let func = trace_span!("get default function")
            .in_scope(|| linker.get_default(&mut wstore, ""))
            .context("failed to get default function")?;

        let mut values = vec![Val::null(); func.ty(&wstore).results().len()];
        trace_span!("execute default function")
            .in_scope(|| func.call(wstore, Default::default(), &mut values))
            .context("failed to execute default function")?;
        
        Ok(values)
    }
}
