import java.io.FileWriter;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Reference;

public class ExportCallGraph extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String output = args.length > 0 ? args[0] : "callgraph.json";
        StringBuilder json = new StringBuilder("[");
        boolean first = true;
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            Function caller = functions.next();
            AddressIterator addresses = caller.getBody().getAddresses(true);
            while (addresses.hasNext()) {
                Reference[] references = currentProgram.getReferenceManager().getReferencesFrom(addresses.next());
                for (Reference reference : references) {
                    if (!reference.getReferenceType().isCall()) {
                        continue;
                    }
                    Function callee = currentProgram.getFunctionManager().getFunctionAt(reference.getToAddress());
                    if (callee == null) {
                        callee = currentProgram.getFunctionManager().getFunctionContaining(reference.getToAddress());
                    }
                    if (callee == null) {
                        continue;
                    }
                    if (!first) {
                        json.append(",");
                    }
                    first = false;
                    json.append("{")
                        .append("\"caller\":\"").append(esc(caller.getName())).append("\",")
                        .append("\"callee\":\"").append(esc(callee.getName())).append("\",")
                        .append("\"caller_address\":\"").append(caller.getEntryPoint().toString()).append("\",")
                        .append("\"callee_address\":\"").append(callee.getEntryPoint().toString()).append("\"")
                        .append("}");
                }
            }
        }
        json.append("]");
        try (FileWriter writer = new FileWriter(output)) {
            writer.write(json.toString());
        }
    }

    private String esc(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder escaped = new StringBuilder();
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '\\':
                    escaped.append("\\\\");
                    break;
                case '"':
                    escaped.append("\\\"");
                    break;
                case '\b':
                    escaped.append("\\b");
                    break;
                case '\f':
                    escaped.append("\\f");
                    break;
                case '\n':
                    escaped.append("\\n");
                    break;
                case '\r':
                    escaped.append("\\r");
                    break;
                case '\t':
                    escaped.append("\\t");
                    break;
                default:
                    if (character < 0x20) {
                        escaped.append(String.format("\\u%04x", (int) character));
                    } else {
                        escaped.append(character);
                    }
            }
        }
        return escaped.toString();
    }
}
