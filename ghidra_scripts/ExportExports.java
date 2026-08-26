import java.io.FileWriter;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

public class ExportExports extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String output = args.length > 0 ? args[0] : "exports.json";
        StringBuilder json = new StringBuilder("[");
        SymbolIterator symbols = currentProgram.getSymbolTable().getSymbolIterator(true);
        boolean first = true;
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            if (!symbol.isPrimary() || symbol.isExternal()) {
                continue;
            }
            if (!first) {
                json.append(",");
            }
            first = false;
            json.append("{")
                .append("\"name\":\"").append(esc(symbol.getName())).append("\",")
                .append("\"address\":\"").append(symbol.getAddress().toString()).append("\"")
                .append("}");
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

