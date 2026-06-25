use crate::types::{HeapBlock, Region, RegionEntry};
use quick_junit::{NonSuccessKind, Report, TestCase, TestCaseStatus, TestSuite};
use std::error::Error;
use std::fs;
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

pub fn heap_to_json_file<P: AsRef<Path>>(
    file_path: P,
    blocks: Vec<HeapBlock>,
) -> Result<(), Box<dyn Error>> {
    let json_str = serde_json::to_string_pretty(&blocks)?;
    fs::write(file_path, json_str)?;
    Ok(())
}

pub fn region_to_json_file<P: AsRef<Path>>(
    file_path: P,
    regions: Vec<Region>,
    labels: Vec<&str>,
) -> Result<(), Box<dyn Error>> {
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
    let json_str = serde_json::to_string_pretty(&entries)?;
    fs::write(file_path, json_str)?;
    Ok(())
}

pub fn heap_to_csv_file<P: AsRef<Path>>(
    file_path: P,
    blocks: Vec<HeapBlock>,
) -> Result<(), Box<dyn Error>> {
    let file = File::create(file_path)?;

    let mut wtr = csv::Writer::from_writer(file);

    for block in blocks {
        wtr.serialize(&block)?;
    }
    wtr.flush()?;
    Ok(())
}

pub fn region_to_csv_file<P: AsRef<Path>>(
    file_path: P,
    regions: Vec<Region>,
) -> Result<(), Box<dyn Error>> {
    let file = File::create(file_path)?;

    let mut wtr = csv::Writer::from_writer(file);

    for region in regions {
        wtr.serialize(&region)?;
    }
    wtr.flush()?;
    Ok(())
}

pub fn heap_to_junit_file<P: AsRef<Path>>(
    file_path: P,
    blocks: Vec<HeapBlock>,
) -> Result<(), Box<dyn Error>> {
    let mut report = Report::new("mvis-heap-analysis");
    let mut suite = TestSuite::new("heap-blocks");

    for block in &blocks {
        let case_name = format!("block@{:#x}", block.address);

        let status = if block.is_free {
            TestCaseStatus::success()
        } else {
            let description = format!(
                "Active (non-freed) heap block: address={:#x}, size={} bytes, protect={:?}",
                block.address, block.size, block.vm_protect
            );
            let mut s = TestCaseStatus::non_success(NonSuccessKind::Failure);
            s.set_message(description);
            s
        };

        let mut case = TestCase::new(case_name, status);
        case.add_property(("address", format!("{:#x}", block.address).as_str()));
        case.add_property(("size_bytes", block.size.to_string().as_str()));
        case.add_property(("is_free", block.is_free.to_string().as_str()));
        case.add_property(("vm_protect", format!("{:?}", block.vm_protect).as_str()));

        suite.add_test_case(case);
    }

    report.add_test_suite(suite);

    let xml = report.to_string()?;
    fs::write(file_path, xml)?;
    Ok(())
}
