use gimli::{
    AttributeValue, DW_AT_abstract_origin, DW_AT_call_file, DW_AT_call_line, DW_AT_decl_file,
    DW_AT_decl_line, DW_AT_linkage_name, DW_AT_specification, DW_TAG_compile_unit,
    DW_TAG_inlined_subroutine, DW_TAG_subprogram, DebuggingInformationEntry, DwTag, Dwarf,
    DwarfSections, EndianSlice, EntriesTreeNode, Reader, RunTimeEndian, SectionId, Unit,
    UnitHeader, UnitOffset,
};
use object::{Object, ObjectSection};
use rustc_demangle::demangle;
use solana_pubkey::Pubkey;
use std::{collections::HashMap, fs, io, path::PathBuf};

#[derive(Clone, Debug)]
pub struct LineMapping {
    pub file: PathBuf,
    pub line: u64,
}

#[derive(Debug, Clone)]
pub struct TraceDieNode<R: Reader> {
    pub call_mapping: Option<LineMapping>,
    pub decl_mapping: LineMapping,
    pub function_signature: String,
    pub parent_offset: UnitOffset<<R as Reader>::Offset>,
}

#[derive(Debug)]
pub struct Interval<R: Reader> {
    begin: u64,
    end: u64,
    pub die_offset: UnitOffset<<R as Reader>::Offset>,
    pub depth: u32,
}

pub struct IntervalNode<R: Reader> {
    center: u64,
    overlaps: Vec<Interval<R>>,
    left: Option<Box<IntervalNode<R>>>,
    right: Option<Box<IntervalNode<R>>>,
}

impl<R: Reader> IntervalNode<R> {
    pub fn search<'a>(&'a self, pc: &u64, results: &mut Vec<&'a Interval<R>>) {
        let pc_lookup = *pc;

        for o in &self.overlaps {
            if o.begin <= pc_lookup && pc_lookup < o.end {
                results.push(o);
            }
        }

        if pc_lookup < self.center {
            if let Some(left) = &self.left {
                left.search(pc, results);
            }
        }

        if pc_lookup > self.center {
            if let Some(right) = &self.right {
                right.search(pc, results);
            }
        }
    }

    pub fn search_first<'a>(&'a self, pc: &u64) -> Option<&'a Interval<R>> {
        let pc_lookup = *pc;

        for o in &self.overlaps {
            if o.begin <= pc_lookup && pc_lookup < o.end {
                return Some(o);
            }
        }

        if pc_lookup < self.center {
            if let Some(left) = &self.left {
                left.search_first(pc);
            }
        }

        if pc_lookup > self.center {
            if let Some(right) = &self.right {
                right.search_first(pc);
            }
        }

        None
    }

    pub fn search_deepest<'a>(&'a self, pc: &u64) -> Option<&'a Interval<R>> {
        let pc_lookup = *pc;
        let mut best: Option<&Interval<R>> = None;

        for iv in &self.overlaps {
            if iv.begin <= pc_lookup && pc_lookup < iv.end {
                if best.map_or(true, |b| iv.depth > b.depth) {
                    best = Some(iv);
                }
            }
        }

        if pc_lookup < self.center {
            if let Some(left) = &self.left {
                if let Some(candidate) = left.search_deepest(pc) {
                    if best.map_or(true, |b| candidate.depth > b.depth) {
                        best = Some(candidate);
                    }
                }
            }
        } else if pc_lookup > self.center {
            if let Some(right) = &self.right {
                if let Some(candidate) = right.search_deepest(pc) {
                    if best.map_or(true, |b| candidate.depth > b.depth) {
                        best = Some(candidate);
                    }
                }
            }
        }

        best
    }
}

pub struct DwarfProgram {
    pub owned_dwarf: &'static OwnedDwarf,
    pub path: PathBuf,
    pub significant_instruction_map:
        HashMap<UnitOffset, TraceDieNode<EndianSlice<'static, RunTimeEndian>>>,
    pub interval_tree: Box<IntervalNode<EndianSlice<'static, RunTimeEndian>>>,
    pub root_instruction_unit: HashMap<UnitOffset, UnitHeader<EndianSlice<'static, RunTimeEndian>>>,
}

pub struct DwarfParser {
    pub project_root: String,
    pub dwarf_programs: HashMap<Pubkey, DwarfProgram>,
}

pub struct OwnedDwarf {
    sections: DwarfSections<Vec<u8>>,
}

impl OwnedDwarf {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let data = fs::read(path)?;
        let obj = object::File::parse(&*data)?;

        // println!("parsed path {}", path);

        let sections = DwarfSections::load(|id: SectionId| -> io::Result<Vec<u8>> {
            match obj.section_by_name(id.name()) {
                Some(s) => Ok(s
                    .uncompressed_data()
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
                    .into_owned()),
                None => Ok(Vec::new()),
            }
        })?;

        Ok(Self { sections })
    }

    pub fn dwarf(&self) -> Dwarf<EndianSlice<'_, RunTimeEndian>> {
        self.sections
            .borrow(|bytes| EndianSlice::new(bytes, RunTimeEndian::Little))
    }
}

impl DwarfParser {
    pub fn new(project_root: String, dwarf_sources: HashMap<Pubkey, PathBuf>) -> Self {
        let mut dwarf_programs: HashMap<Pubkey, DwarfProgram> = HashMap::new();

        for (program_address, program_path) in dwarf_sources {
            // println!("{} {}", program_address, program_path.to_string_lossy());
            // let owned_dwarf = OwnedDwarf::load(program_path.clone().to_str().unwrap()).unwrap();
            let owned_dwarf: &'static OwnedDwarf = Box::leak(Box::new(
                OwnedDwarf::load(program_path.to_str().unwrap()).unwrap(),
            ));
            let (hash_map, interval_tree, hash_root_units) =
                build_lookup_trees(&owned_dwarf.dwarf(), project_root.as_str()).unwrap();

            dwarf_programs.insert(
                program_address,
                DwarfProgram {
                    path: program_path,
                    owned_dwarf: owned_dwarf,
                    significant_instruction_map: hash_map,
                    interval_tree: interval_tree,
                    root_instruction_unit: hash_root_units,
                },
            );
        }

        DwarfParser {
            project_root: project_root,
            dwarf_programs: dwarf_programs,
        }
    }
}

pub fn build_lookup_trees(
    dwarf: &Dwarf<EndianSlice<'static, RunTimeEndian>>,
    project_directory_path: &str,
) -> anyhow::Result<(
    HashMap<UnitOffset<usize>, TraceDieNode<EndianSlice<'static, RunTimeEndian>>>,
    Box<IntervalNode<EndianSlice<'static, RunTimeEndian>>>,
    HashMap<UnitOffset<usize>, UnitHeader<EndianSlice<'static, RunTimeEndian>, usize>>,
)> {
    // let owned_dwarf = OwnedDwarf::load(program_path.to_str().unwrap()).unwrap();
    // let dwarf = owned_dwarf.dwarf();

    let mut trace_mappings = HashMap::new();
    let mut trace_ranges = vec![];
    let mut die_units = HashMap::new();

    let mut units = dwarf.units();

    while let Some(uheader) = units.next()? {
        let unit = dwarf.unit(uheader.clone())?;

        let mut tree = unit.entries_tree(None)?;
        let root = tree.root()?;

        if root.entry().tag() == DW_TAG_compile_unit {
            let _ = descend_dwarf(
                &dwarf,
                project_directory_path,
                None,
                &unit,
                uheader,
                root,
                0,
                &mut trace_mappings,
                &mut trace_ranges,
                &mut die_units,
            );
        }
    }

    let interval_tree = build_interval_tree(trace_ranges).unwrap();

    Ok((trace_mappings, interval_tree, die_units))
}

fn descend_dwarf<'a>(
    dwarf: &Dwarf<EndianSlice<'a, RunTimeEndian>>,
    project_directory_path: &str,
    parent_offset: Option<UnitOffset<usize>>,
    current_unit: &Unit<EndianSlice<'a, RunTimeEndian>>,
    current_unit_header: UnitHeader<EndianSlice<'a, RunTimeEndian>, usize>,
    current_node: EntriesTreeNode<EndianSlice<'a, RunTimeEndian>>,
    current_depth: u32,
    die_mappings: &mut HashMap<UnitOffset<usize>, TraceDieNode<EndianSlice<'a, RunTimeEndian>>>,
    die_ranges: &mut Vec<Interval<EndianSlice<'a, RunTimeEndian>>>,
    die_units: &mut HashMap<UnitOffset<usize>, UnitHeader<EndianSlice<'a, RunTimeEndian>, usize>>,
) -> anyhow::Result<()> {
    let current_entry = current_node.entry();
    let current_tag = current_entry.tag();

    if current_depth == 0 && current_tag != DW_TAG_compile_unit {
        return Ok(());
    }

    let mut next_parent_offset = parent_offset;

    if current_entry.tag() == DW_TAG_subprogram || current_entry.tag() == DW_TAG_inlined_subroutine
    {
        let current_offset = current_entry.offset();

        let trace_die_node = get_trace_die_node(
            &dwarf,
            parent_offset,
            current_unit,
            current_entry,
            current_tag,
        )
        .unwrap();

        if trace_die_node
            .decl_mapping
            .file
            .starts_with(project_directory_path)
            || (trace_die_node.call_mapping.is_some()
                && trace_die_node
                    .call_mapping
                    .as_ref()
                    .unwrap()
                    .file
                    .starts_with(project_directory_path))
        {
            if trace_die_node.parent_offset == current_offset {
                die_units.insert(current_offset.clone(), current_unit_header.clone());
            }

            die_mappings.insert(current_offset.clone(), trace_die_node.clone());
            next_parent_offset = Some(current_offset);

            let mut current_entry_ranges = dwarf.die_ranges(current_unit, current_entry)?;

            while let Some(r) = current_entry_ranges.next()? {
                die_ranges.push(Interval {
                    begin: r.begin.clone(),
                    end: r.end.clone(),
                    die_offset: current_offset.clone(),
                    depth: current_depth.clone(),
                })
            }
        }
    }

    let mut children = current_node.children();
    while let Some(next_node) = children.next()? {
        let _ = descend_dwarf(
            dwarf,
            project_directory_path,
            next_parent_offset,
            current_unit,
            current_unit_header.clone(),
            next_node,
            current_depth.clone() + 1,
            die_mappings,
            die_ranges,
            die_units,
        );
    }

    Ok(())
}

fn build_interval_tree<R: Reader>(trace_ranges: Vec<Interval<R>>) -> Option<Box<IntervalNode<R>>> {
    if trace_ranges.is_empty() {
        return None;
    }

    let mut points: Vec<u64> = trace_ranges.iter().map(|i| (i.begin + i.end) / 2).collect();
    points.sort();
    let center = points[points.len() / 2];

    let mut overlaps = Vec::new();
    let mut left = Vec::new();
    let mut right = Vec::new();

    for tr in trace_ranges {
        if tr.end < center {
            left.push(tr);
        } else if tr.begin > center {
            right.push(tr);
        } else {
            overlaps.push(tr);
        }
    }

    Some(Box::new(IntervalNode {
        center: center,
        overlaps: overlaps,
        left: build_interval_tree(left),
        right: build_interval_tree(right),
    }))
}

fn strip_hash_suffix(name: &str) -> &str {
    if let Some(idx) = name.rfind("::h") {
        let suffix = &name[idx + 3..];
        if suffix.len() == 16 && suffix.chars().all(|c| c.is_ascii_hexdigit()) {
            return &name[..idx];
        }
    }
    name
}

fn demangle_function(raw: &String) -> String {
    let clean = strip_hash_suffix(&demangle(raw).to_string()).to_string();
    return clean;
}

fn get_trace_die_node<R: Reader>(
    dwarf: &Dwarf<R>,
    parent_offset: Option<UnitOffset<<R>::Offset>>,
    current_unit: &Unit<R>,
    current_entry: &DebuggingInformationEntry<R>,
    current_tag: DwTag,
) -> anyhow::Result<TraceDieNode<R>> {
    let data = collect_subprogram_info(dwarf, current_unit, current_entry, current_tag)?;
    let call_line_mapping: Option<LineMapping> = match data.1.is_some() && data.2.is_some() {
        true => Some(LineMapping {
            file: data.1.unwrap(),
            line: data.2.unwrap(),
        }),
        false => None,
    };

    Ok(TraceDieNode {
        function_signature: data.0.unwrap_or("<none>".to_string()),
        decl_mapping: LineMapping {
            file: data.3.unwrap(),
            line: data.4.unwrap(),
        },
        call_mapping: call_line_mapping,
        parent_offset: parent_offset.unwrap_or(current_entry.offset()),
    })
}

fn collect_subprogram_info<R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    die: &DebuggingInformationEntry<R>,
    tag: DwTag,
) -> anyhow::Result<(
    Option<String>,
    Option<PathBuf>,
    Option<u64>,
    Option<PathBuf>,
    Option<u64>,
)> {
    let mut function_signature: Option<String> = None;
    let mut call_file: Option<PathBuf> = None;
    let mut call_line: Option<u64> = None;
    let mut decl_file: Option<PathBuf> = None;
    let mut decl_line: Option<u64> = None;

    if function_signature.is_none() {
        if let Some(attr) = die.attr(DW_AT_linkage_name)? {
            if let Some(raw) = resolve_str(dwarf, attr.value())? {
                function_signature = Some(demangle_function(&raw));
            }
        }
    }

    if call_file.is_none() {
        if let Some(attr) = die.attr(DW_AT_call_file)? {
            if let AttributeValue::FileIndex(idx) = attr.value() {
                if let Some(lp) = &unit.line_program {
                    if let Some(fe) = lp.header().file(idx) {
                        call_file = Some(resolve_file_path(dwarf, unit, fe, lp.header())?);
                    }
                }
            }
        }
    }

    if call_line.is_none() {
        if let Some(attr) = die.attr(DW_AT_call_line)? {
            if let AttributeValue::Udata(l) = attr.value() {
                call_line = Some(l);
            }
        }
    }

    if decl_file.is_none() {
        if let Some(attr) = die.attr(DW_AT_decl_file)? {
            if let AttributeValue::FileIndex(idx) = attr.value() {
                if let Some(lp) = &unit.line_program {
                    if let Some(fe) = lp.header().file(idx) {
                        decl_file = Some(resolve_file_path(dwarf, unit, fe, lp.header())?);
                    }
                }
            }
        }
    }

    if decl_line.is_none() {
        if let Some(attr) = die.attr(DW_AT_decl_line)? {
            if let AttributeValue::Udata(l) = attr.value() {
                decl_line = Some(l);
            }
        }
    }

    if function_signature.is_none()
        || call_file.is_none()
        || call_line.is_none()
        || decl_file.is_none()
        || decl_line.is_none()
    {
        for attr_kind in [DW_AT_abstract_origin, DW_AT_specification] {
            if let Some(attr) = die.attr(attr_kind)? {
                match attr.value() {
                    AttributeValue::UnitRef(offset) => {
                        let origin = unit.entry(offset)?;
                        let inner = collect_subprogram_info(dwarf, unit, &origin, tag).unwrap();

                        if function_signature.is_none() {
                            function_signature = inner.0;
                        }

                        if call_file.is_none() {
                            call_file = inner.1;
                        }

                        if call_line.is_none() {
                            call_line = inner.2;
                        }

                        if decl_file.is_none() {
                            decl_file = inner.3;
                        }

                        if decl_line.is_none() {
                            decl_line = inner.4;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    Ok((
        function_signature,
        call_file,
        call_line,
        decl_file,
        decl_line,
    ))
}

fn resolve_str<R: gimli::Reader>(
    dwarf: &gimli::Dwarf<R>,
    attr: gimli::AttributeValue<R>,
) -> anyhow::Result<Option<String>> {
    match attr {
        gimli::AttributeValue::String(s) => Ok(Some(s.to_string_lossy()?.into_owned())),
        gimli::AttributeValue::DebugStrRef(off) => {
            let s = dwarf.debug_str.get_str(off)?;
            Ok(Some(s.to_string_lossy()?.into_owned()))
        }
        gimli::AttributeValue::DebugLineStrRef(off) => {
            let s = dwarf.debug_line_str.get_str(off)?;
            Ok(Some(s.to_string_lossy()?.into_owned()))
        }
        _ => Ok(None),
    }
}

pub fn source_location<R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    pc: u64,
    project_root: &String,
) -> anyhow::Result<(Option<PathBuf>, Option<u64>)> {
    let mut best_file: Option<PathBuf> = None;
    let mut best_line: Option<u64> = None;
    if let Some(ref program) = unit.line_program {
        let mut rows = program.clone().rows();
        while let Some((header, row)) = rows.next_row()? {
            let addr = row.address();
            // println!("addr {}", addr);

            // if addr > pc {
            //     if let Some(current_best_file) = best_file.clone() {
            //         if current_best_file.starts_with(project_root) {
            //             break;
            //         }
            //     }
            // }

            if addr == pc {
                if let Some(fe) = row.file(header) {
                    let fname = dwarf.attr_string(unit, fe.path_name())?;
                    let mut path = PathBuf::from(fname.to_string_lossy()?.into_owned());

                    if let Some(dir_attr) = header.directory(fe.directory_index()) {
                        let dir = dwarf.attr_string(unit, dir_attr)?;
                        path = PathBuf::from(dir.to_string_lossy()?.into_owned()).join(path);
                    }

                    if path.is_relative() {
                        if let Some(comp_dir) = unit.comp_dir.as_ref() {
                            let dir = comp_dir.to_string_lossy()?.into_owned();
                            path = PathBuf::from(dir).join(path);
                        }
                    }

                    if path.starts_with(project_root) {
                        best_file = Some(path);
                        best_line = row.line().map(|nz| nz.get());
                    } else {
                        best_file = None;
                        best_line = None;
                    }
                }
            }
        }
    }

    Ok((best_file, best_line))
}

fn resolve_file_path<R: gimli::Reader>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    file: &gimli::FileEntry<R>,
    header: &gimli::LineProgramHeader<R>,
) -> anyhow::Result<PathBuf> {
    let s = dwarf.attr_string(unit, file.path_name())?;
    let mut path = PathBuf::from(s.to_string_lossy()?.into_owned());

    if let Some(dir_attr) = header.directory(file.directory_index()) {
        let s = dwarf.attr_string(unit, dir_attr)?;
        let dir_path = PathBuf::from(s.to_string_lossy()?.into_owned());
        path = dir_path.join(path);
    }

    if path.is_relative() {
        if let Some(comp_dir_attr) = unit.comp_dir.as_ref() {
            let comp_dir = comp_dir_attr.to_string_lossy()?.into_owned();
            path = PathBuf::from(comp_dir).join(path);
        }
    }

    Ok(path)
}

pub fn get_pc_function_trace<R: Reader>(
    pc: &u64,
    trace_mappings: &HashMap<UnitOffset<<R>::Offset>, TraceDieNode<R>>,
    interval_tree: &Box<IntervalNode<R>>,
) {
    if let Some(interval) = interval_tree.search_deepest(pc) {
        let mut tracing = true;
        let mut current_offset = interval.die_offset;
        while tracing {
            let trace_die_node = trace_mappings.get(&current_offset).unwrap();
            if trace_die_node.parent_offset == current_offset {
                tracing = false;
            } else {
                current_offset = trace_die_node.parent_offset;
            }
        }
    }
}
