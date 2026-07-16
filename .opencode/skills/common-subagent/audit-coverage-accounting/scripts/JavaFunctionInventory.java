import com.sun.source.tree.BlockTree;
import com.sun.source.tree.ClassTree;
import com.sun.source.tree.CompilationUnitTree;
import com.sun.source.tree.LambdaExpressionTree;
import com.sun.source.tree.MethodTree;
import com.sun.source.tree.Tree;
import com.sun.source.util.JavacTask;
import com.sun.source.util.SourcePositions;
import com.sun.source.util.TreePath;
import com.sun.source.util.TreePathScanner;
import com.sun.source.util.Trees;

import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Locale;

public final class JavaFunctionInventory {
    private JavaFunctionInventory() {}

    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.err.println("Usage: JavaFunctionInventory <root> <source-list> <output-ndjson>");
            System.exit(1);
        }
        Path root = Paths.get(args[0]).toAbsolutePath().normalize();
        List<Path> sources = Files.readAllLines(Paths.get(args[1]), StandardCharsets.UTF_8).stream()
                .filter(line -> !line.isBlank())
                .map(root::resolve)
                .map(Path::normalize)
                .toList();
        Path output = Paths.get(args[2]);

        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) throw new IllegalStateException("A full JDK is required; Java compiler unavailable");

        DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
        try (StandardJavaFileManager fileManager = compiler.getStandardFileManager(diagnostics, Locale.ROOT, StandardCharsets.UTF_8);
             BufferedWriter writer = Files.newBufferedWriter(output, StandardCharsets.UTF_8)) {
            Iterable<? extends JavaFileObject> objects = fileManager.getJavaFileObjectsFromPaths(sources);
            JavacTask task = (JavacTask) compiler.getTask(null, fileManager, diagnostics,
                    List.of("-proc:none", "-Xlint:none"), null, objects);
            Iterable<? extends CompilationUnitTree> units = task.parse();
            Trees trees = Trees.instance(task);
            SourcePositions positions = trees.getSourcePositions();

            for (CompilationUnitTree unit : units) {
                Path sourcePath = Paths.get(unit.getSourceFile().toUri()).toAbsolutePath().normalize();
                String rel = normalize(root.relativize(sourcePath).toString());
                writer.write("FILE\t" + object(
                        field("path", rel),
                        field("package", unit.getPackageName() == null ? "" : unit.getPackageName().toString())
                ));
                writer.newLine();
                CharSequence content = unit.getSourceFile().getCharContent(true);
                new Scanner(root, unit, positions, content, writer).scan(unit, null);
            }

            for (Diagnostic<? extends JavaFileObject> diagnostic : diagnostics.getDiagnostics()) {
                if (diagnostic.getKind() != Diagnostic.Kind.ERROR) continue;
                String path = "";
                if (diagnostic.getSource() != null) {
                    Path sourcePath = Paths.get(diagnostic.getSource().toUri()).toAbsolutePath().normalize();
                    path = normalize(root.relativize(sourcePath).toString());
                }
                writer.write("DIAGNOSTIC\t" + object(
                        field("path", path),
                        numberField("line", diagnostic.getLineNumber()),
                        numberField("column", diagnostic.getColumnNumber()),
                        field("code", diagnostic.getCode()),
                        field("message", diagnostic.getMessage(Locale.ROOT))
                ));
                writer.newLine();
            }
        }
    }

    private static final class Scanner extends TreePathScanner<Void, Void> {
        private final Path root;
        private final CompilationUnitTree unit;
        private final SourcePositions positions;
        private final CharSequence source;
        private final BufferedWriter writer;
        private final Deque<String> classes = new ArrayDeque<>();
        private int anonymousCounter = 0;

        Scanner(Path root, CompilationUnitTree unit, SourcePositions positions, CharSequence source, BufferedWriter writer) {
            this.root = root;
            this.unit = unit;
            this.positions = positions;
            this.source = source;
            this.writer = writer;
        }

        @Override
        public Void visitClass(ClassTree node, Void unused) {
            long start = positions.getStartPosition(unit, node);
            String name = node.getSimpleName().toString();
            if (name.isBlank()) name = "<anonymous@" + line(start) + ":" + (++anonymousCounter) + ">";
            classes.addLast(name);
            try {
                return super.visitClass(node, unused);
            } finally {
                classes.removeLast();
            }
        }

        @Override
        public Void visitMethod(MethodTree node, Void unused) {
            String name = node.getName().toString();
            String kind = name.equals("<init>") ? "constructor" : "method";
            String displayName = kind.equals("constructor") ? (classes.peekLast() == null ? "<init>" : classes.peekLast()) : name;
            String params = node.getParameters().stream().map(p -> p.getType() == null ? "?" : p.getType().toString()).reduce((a, b) -> a + "," + b).orElse("");
            emit(node, kind, displayName, displayName + "(" + params + ")");
            return super.visitMethod(node, unused);
        }

        @Override
        public Void visitLambdaExpression(LambdaExpressionTree node, Void unused) {
            long start = positions.getStartPosition(unit, node);
            String name = "<lambda@" + line(start) + ":" + column(start) + ">";
            emit(node, "lambda", name, name + "(" + node.getParameters().size() + ")");
            return super.visitLambdaExpression(node, unused);
        }

        @Override
        public Void visitBlock(BlockTree node, Void unused) {
            TreePath parentPath = getCurrentPath().getParentPath();
            if (parentPath != null && parentPath.getLeaf() instanceof ClassTree) {
                long start = positions.getStartPosition(unit, node);
                String kind = node.isStatic() ? "static-initializer" : "instance-initializer";
                String name = "<" + kind + "@" + line(start) + ">";
                emit(node, kind, name, name);
            }
            return super.visitBlock(node, unused);
        }

        private void emit(Tree node, String kind, String name, String signature) {
            try {
                long start = positions.getStartPosition(unit, node);
                long end = positions.getEndPosition(unit, node);
                if (start < 0) return;
                String rel = normalize(root.relativize(Paths.get(unit.getSourceFile().toUri()).toAbsolutePath().normalize()).toString());
                String packageName = unit.getPackageName() == null ? "" : unit.getPackageName().toString();
                List<String> parts = new ArrayList<>();
                if (!packageName.isBlank()) parts.add(packageName);
                parts.addAll(classes);
                parts.add(name);
                int safeStart = (int) Math.min(Math.max(start, 0), source.length());
                int safeEnd = end < 0 ? safeStart : (int) Math.min(Math.max(end, safeStart), source.length());
                writer.write("FUNCTION\t" + object(
                        field("path", rel),
                        field("kind", kind),
                        field("name", name),
                        field("qualified_name", String.join(".", parts)),
                        field("signature", signature),
                        numberField("line_start", line(start)),
                        numberField("column_start", column(start)),
                        numberField("line_end", end < 0 ? line(start) : line(end)),
                        field("code_sha256", sha256(source.subSequence(safeStart, safeEnd).toString()))
                ));
                writer.newLine();
            } catch (IOException error) {
                throw new RuntimeException(error);
            }
        }

        private long line(long position) {
            return position < 0 ? 0 : unit.getLineMap().getLineNumber(position);
        }

        private long column(long position) {
            return position < 0 ? 0 : unit.getLineMap().getColumnNumber(position);
        }
    }

    private static String normalize(String value) {
        return value.replace('\\', '/');
    }

    private static String sha256(String value) {
        try {
            byte[] bytes = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder result = new StringBuilder();
            for (byte b : bytes) result.append(String.format("%02x", b));
            return result.toString();
        } catch (Exception error) {
            throw new RuntimeException(error);
        }
    }

    private static String field(String name, String value) {
        return quote(name) + ":" + quote(value == null ? "" : value);
    }

    private static String numberField(String name, long value) {
        return quote(name) + ":" + value;
    }

    private static String object(String... fields) {
        return "{" + String.join(",", fields) + "}";
    }

    private static String quote(String value) {
        StringBuilder out = new StringBuilder("\"");
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '\\' -> out.append("\\\\");
                case '"' -> out.append("\\\"");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) out.append(String.format("\\u%04x", (int) c));
                    else out.append(c);
                }
            }
        }
        return out.append('"').toString();
    }
}
