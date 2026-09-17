use std::{
  collections::{BTreeMap, HashSet},
  io::{Cursor, Write},
  time::Instant,
};

use assetpack_core::{
  Codec, DEFAULT_FORMAT_TAG, FileHint, FileReadLimits, FileReader, FileTransformConfig, Hash32, ObjectKind, ObjectRecord, PackOpenPolicy,
  ParsedSealedPack, SealedPackBuilder, TransformDecoderRegistry, TransformSelector, build_recipe,
  file_transform::SelectionReport,
  pipeline::{DefaultChunkCompressor, Pipeline, PipelineConfig},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
  let args: Vec<_> = std::env::args().skip(1).collect();
  if args.len() < 2 {
    return Err("usage: pdf_bench baseline|preprocess|verify|selector|pack FILE...".into());
  }
  let mut seen = HashSet::new();
  for path in &args[1..] {
    let input = std::fs::read(path)?;
    println!("file={path} input_bytes={}", input.len());
    let start = Instant::now();
    match args[0].as_str() {
      "baseline" => {
        for level in [6, 19] {
          let start = Instant::now();
          let encoded = zstd::encode_all(Cursor::new(&input), level)?;
          assert_eq!(zstd::decode_all(Cursor::new(&encoded))?, input);
          println!(
            "zstd{level} bytes={} roundtrip_s={:.3}",
            encoded.len(),
            start.elapsed().as_secs_f64()
          );
        }
        lzma(&input)?;
      }
      "preprocess" | "verify" => {
        let config = precomp2::EncodeConfig {
          enable_png_webp: true,
          enable_pdf_predictor: true,
          ..Default::default()
        };
        let (encoded, stats) = precomp2::encode_bytes_with_stats(&input, &config)?;
        println!(
          "pcf2 bytes={} encode_s={:.3} stats={stats:?}",
          encoded.len(),
          start.elapsed().as_secs_f64()
        );
        let decode = Instant::now();
        assert_eq!(precomp2::decode_bytes(&encoded, &Default::default())?, input);
        println!("pcf2 decode_s={:.3} exact=true", decode.elapsed().as_secs_f64());
        let compressed = zstd::encode_all(Cursor::new(&encoded), 6)?;
        println!("pcf2_zstd6 bytes={}", compressed.len());
        if args[0] != "verify" {
          lzma(&encoded)?;
        }
      }
      "selector" | "pack" => {
        let config = FileTransformConfig {
          min_size: 0,
          ..Default::default()
        };
        let selector = TransformSelector::new(config, None, assetpack_transform_precomp2::default_specs());
        let pipeline = Pipeline::new(PipelineConfig {
          discard_payload: true,
          ..Default::default()
        });
        let hint = FileHint {
          size: input.len() as u64,
          extension: Some("pdf".into()),
          head: None,
        };
        let hash = Hash32::sha3_256(&input);
        let mut report = SelectionReport::default();
        let selection = selector.select_with_report(input, &hint, hash, &pipeline, &DefaultChunkCompressor, &mut report)?;
        println!(
          "selected={}:{} elapsed_s={:.3} report={report:?}",
          selection.transform_id,
          selection.transform_version,
          start.elapsed().as_secs_f64()
        );
        if args[0] == "pack" {
          let pipeline = Pipeline::new(PipelineConfig::default());
          let plan = pipeline.run_with_selection(selection, Some("pdf"), &DefaultChunkCompressor)?;
          let refs = plan.chunks.iter().map(|chunk| (chunk.hash, chunk.raw_len)).collect::<Vec<_>>();
          let recipe = build_recipe(
            plan.original_size,
            &refs,
            plan.original_hash,
            plan.transform_id,
            plan.transform_version,
          );
          let root = Hash32::sha3_256(&recipe);
          let recipe_len = recipe.len();
          let mut objects = BTreeMap::new();
          for chunk in plan.chunks {
            objects.insert(
              chunk.hash,
              ObjectRecord {
                hash: chunk.hash,
                kind: ObjectKind::Chunk,
                decoded_len: chunk.raw_len as u64,
                codec: chunk.codec,
                stored_bytes: chunk.payload.unwrap(),
              },
            );
          }
          objects.insert(
            root,
            ObjectRecord {
              hash: root,
              kind: ObjectKind::Recipe,
              decoded_len: recipe.len() as u64,
              codec: Codec::Raw,
              stored_bytes: recipe,
            },
          );
          let payload_bytes: usize = objects.values().map(|object| object.stored_bytes.len()).sum();
          let incremental_bytes: usize = objects
            .values()
            .filter(|object| seen.insert(object.hash))
            .map(|object| object.stored_bytes.len())
            .sum();
          let bytes = SealedPackBuilder::build_plain(DEFAULT_FORMAT_TAG, root, objects.into_values())?;
          println!(
            "pack_bytes={} recipe_bytes={recipe_len} container_overhead={} incremental_unique_payload={incremental_bytes}",
            bytes.len(),
            bytes.len() - payload_bytes
          );
          let parsed = ParsedSealedPack::open(&bytes, DEFAULT_FORMAT_TAG, PackOpenPolicy::PlainAllowed)?;
          let source = parsed.open_plain()?;
          let registry = TransformDecoderRegistry::new(assetpack_transform_precomp2::default_decoders(&FileTransformConfig::default()))?;
          let limits = FileReadLimits {
            max_original_file_bytes: 1 << 32,
            max_stored_stream_bytes: 1 << 32,
            ..Default::default()
          };
          let restored = FileReader::new(&source, &registry, limits).read_file(root)?;
          assert_eq!(Hash32::sha3_256(&restored), hash);
          println!("pack_exact=true total_s={:.3}", start.elapsed().as_secs_f64());
        }
      }
      _ => return Err("unknown mode".into()),
    }
  }
  Ok(())
}

fn lzma(input: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
  let start = Instant::now();
  let mut options = lzma_rust2::Lzma2Options::with_preset(6);
  options.lzma_options.dict_size = 64 * 1024 * 1024;
  let mut encoded = Vec::new();
  let mut writer = lzma_rust2::Lzma2Writer::new(&mut encoded, options);
  writer.write_all(input)?;
  writer.finish()?;
  println!(
    "lzma2_p6_dict64m bytes={} encode_s={:.3}",
    encoded.len(),
    start.elapsed().as_secs_f64()
  );
  let mut restored = Vec::new();
  std::io::Read::read_to_end(
    &mut lzma_rust2::Lzma2Reader::new(Cursor::new(encoded), 64 * 1024 * 1024, None),
    &mut restored,
  )?;
  assert_eq!(restored, input);
  Ok(())
}
