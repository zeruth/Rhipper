// Exports the program's structures, unions and typedefs: what translate32.py needs to turn the
// decompiler's member access (`ptd->_thandle`, `local_6c.dwFlags`) into reads at offsets. One JSON
// document:
//   {"composites": {name: {"size", "union", "fields": [[name, offset, length, type], ...]}},
//    "typedefs": {name: base type name}}
// Names are the ones the decompiler prints; a name defined in several categories keeps the first
// (the duplicates are listed under "duplicates").
//
// Usage (headless): -postScript ExportTypes.java <out.json>
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeSet;

public class ExportTypes extends GhidraScript {

    private static String esc(String s) {
        StringBuilder b = new StringBuilder(s.length() + 8);
        for (char c : s.toCharArray()) {
            if (c == '"' || c == '\\') b.append('\\').append(c);
            else if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
            else b.append(c);
        }
        return b.toString();
    }

    @Override
    public void run() throws Exception {
        String out = getScriptArgs()[0];
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        Map<String, String> composites = new LinkedHashMap<>();
        Map<String, String> typedefs = new LinkedHashMap<>();
        TreeSet<String> duplicates = new TreeSet<>();
        // (every type the program lists, and the composites they reach that it does not: a typedef's
        // base, a field's type through arrays and pointers. `locrefcount` names `localerefcount`, which
        // the program never listed, and threadlocaleinfostruct.lc_category had no layout, 2026-10-23)
        java.util.ArrayDeque<DataType> work = new java.util.ArrayDeque<>();
        java.util.Set<DataType> seen = new java.util.HashSet<>();
        Iterator<DataType> all = dtm.getAllDataTypes();
        while (all.hasNext()) work.add(all.next());
        while (!work.isEmpty() && !monitor.isCancelled()) {
            DataType dt = work.poll();
            if (!seen.add(dt)) continue;
            if (dt instanceof TypeDef td) work.add(td.getBaseDataType());
            if (dt instanceof ghidra.program.model.data.Array ar) work.add(ar.getDataType());
            if (dt instanceof ghidra.program.model.data.Pointer pt && pt.getDataType() != null) work.add(pt.getDataType());
            if (dt instanceof Composite cc) for (DataTypeComponent dc : cc.getDefinedComponents()) work.add(dc.getDataType());
            String name = dt.getName();
            if (dt instanceof Composite) {
                Composite c = (Composite) dt;
                if (composites.containsKey(name)) {
                    duplicates.add(name);
                    continue;
                }
                StringBuilder f = new StringBuilder();
                for (DataTypeComponent dc : c.getDefinedComponents()) {
                    if (f.length() > 0) f.append(',');
                    String fname = dc.getFieldName() != null ? dc.getFieldName() : dc.getDefaultFieldName();
                    f.append(String.format("[\"%s\",%d,%d,\"%s\"]", esc(fname), dc.getOffset(), dc.getLength(),
                            esc(dc.getDataType().getDisplayName())));
                }
                composites.put(name, String.format("{\"size\":%d,\"union\":%b,\"fields\":[%s]}",
                        c.getLength(), c instanceof Union, f));
            } else if (dt instanceof TypeDef) {
                if (!typedefs.containsKey(name)) {
                    typedefs.put(name, ((TypeDef) dt).getBaseDataType().getDisplayName());
                }
            }
        }
        try (PrintWriter w = new PrintWriter(new FileWriter(out))) {
            w.println("{\"composites\": {");
            boolean first = true;
            for (Map.Entry<String, String> e : composites.entrySet()) {
                w.printf("%s\"%s\": %s%n", first ? " " : ",", esc(e.getKey()), e.getValue());
                first = false;
            }
            w.println("}, \"typedefs\": {");
            first = true;
            for (Map.Entry<String, String> e : typedefs.entrySet()) {
                w.printf("%s\"%s\": \"%s\"%n", first ? " " : ",", esc(e.getKey()), esc(e.getValue()));
                first = false;
            }
            w.print("}, \"duplicates\": [");
            first = true;
            for (String d : duplicates) {
                w.printf("%s\"%s\"", first ? "" : ",", esc(d));
                first = false;
            }
            w.println("]}");
        }
        println("ExportTypes: wrote " + composites.size() + " composites, " + typedefs.size() + " typedefs ("
                + duplicates.size() + " names defined twice) to " + out);
    }
}
