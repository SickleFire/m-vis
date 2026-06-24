use crate::types::{HeapBlock, Region, RegionEntry};
use std::io;
use std::error::Error;
use std::fs::File;
use std::path::Path;

pub enum FormatType {
    Json,
    CSV,
    Junit,
}

pub fn heap_to_json(blocks: Vec<HeapBlock>) -> Result<String, serde_json::Error> {
    let json_str = serde_json::to_string_pretty(&blocks)?;
    Ok(json_str)
}

pub fn region_to_json(
    regions: Vec<Region>,
    labels: Vec<&str>,
) -> Result<String, serde_json::Error> {
    let entries: Vec<RegionEntry> = regions
        .iter()
        .zip(labels.iter())
        .map(|(r, l)| RegionEntry {
            base: r.base,
            size: r.size,
            state: r.state.clone(),
            kind: r.kind.clone(),
            protect: r.protect.clone(),
            name: r.name.clone(),
            label: l.to_string(),
        })
        .collect();
    let json_str = serde_json::to_string_pretty(&entries).unwrap();
    Ok(json_str)
}

pub fn heap_to_csv<P: AsRef<Path>>(file_path: P, blocks: Vec<HeapBlock>) -> Result<(), Box<dyn Error>> {
    let file = File::create(file_path)?;

    let mut wtr = csv::Writer::from_writer(file);

    for block in blocks {
        wtr.serialize(&block)?;
    }
    wtr.flush()?;
    Ok(())
}

pub fn region_to_csv<P: AsRef<Path>>(file_path: P, regions: Vec<Region>) -> Result<(), Box<dyn Error>> {
    let file = File::create(file_path)?;

    let mut wtr = csv::Writer::from_writer(file);

    for region in regions {
        wtr.serialize(&region)?;
    }
    wtr.flush()?;
    Ok(())
}
