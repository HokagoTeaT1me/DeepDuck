import java.io.FileWriter;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class ExportFunctions extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String output = args.length > 0 ? args[0] : "functions.json";
        StringBuilder json = new StringBuilder("[");
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        boolean first = true;
        while (functions.hasNext()) {
            Function function = functions.next();
            if (!first) {
                json.append(",");
            }
            first = false;
            json.append("{")
                .append("\"name\":\"").append(esc(function.getName())).append("\",")
                .append("\"address\":\"").append(function.getEntryPoint().toString()).append("\",")
                .append("\"size\":").append(function.getBody().getNumAddresses()).append(",")
                .append("\"is_external\":").append(function.isExternal()).append(",")
                .append("\"is_thunk\":").append(function.isThunk())
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

