// Marks x86 PIC get_pc_thunk.* helpers with the cspec call-fixup so the decompiler resolves GOT-relative addresses.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import java.util.*;

public class FixThunks extends GhidraScript {
    @Override
    public void run() throws Exception {
        Map<String,String> pats = new LinkedHashMap<>();
        pats.put("8b1c24c3", "get_pc_thunk_bx");
        pats.put("8b0424c3", "get_pc_thunk_ax");
        pats.put("8b0c24c3", "get_pc_thunk_cx");
        pats.put("8b1424c3", "get_pc_thunk_dx");
        pats.put("8b3424c3", "get_pc_thunk_si");
        pats.put("8b3c24c3", "get_pc_thunk_di");
        pats.put("8b2c24c3", "get_pc_thunk.bp");
        int n = 0;
        for (Map.Entry<String,String> e : pats.entrySet()) {
            String h = e.getKey();
            byte[] pat = new byte[4];
            for (int i = 0; i < 4; i++) pat[i] = (byte) Integer.parseInt(h.substring(2*i, 2*i+2), 16);
            ghidra.program.model.address.Address a = currentProgram.getMinAddress();
            while (true) {
                a = currentProgram.getMemory().findBytes(a, pat, null, true, monitor);
                if (a == null) break;
                Function f = getFunctionAt(a);
                if (f == null) {
                    disassemble(a);
                    f = createFunction(a, null);
                }
                if (f != null) { f.setCallFixup(e.getValue()); n++; println("fixup " + e.getValue() + " @ " + a); }
                ghidra.program.model.address.Address q = a.subtract(1);
                int guard = 0;
                while (guard++ < 16 && (currentProgram.getMemory().getByte(q) & 0xff) == 0x90) {
                    Function g = getFunctionAt(q);
                    if (g == null) { g = getFunctionContaining(q); }
                    if (g != null) { g.setCallFixup(e.getValue()); n++; println("fixup(pad) " + e.getValue() + " @ " + g.getEntryPoint()); }
                    q = q.subtract(1);
                }
                {   Function g = getFunctionContaining(a); if (g != null && !g.getEntryPoint().equals(a)) { g.setCallFixup(e.getValue()); n++; println("fixup(containing) @ " + g.getEntryPoint()); } }
                a = a.add(1);
            }
        }
        println("call-fixups set: " + n);
    }
}
