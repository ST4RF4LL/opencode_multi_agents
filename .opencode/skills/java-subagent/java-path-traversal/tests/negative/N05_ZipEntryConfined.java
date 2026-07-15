import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class N05_ZipEntryConfined {
    public void safe(InputStream zipStream, Path destDir) throws Exception {
        Path base = destDir.toAbsolutePath().normalize();
        try (ZipInputStream zis = new ZipInputStream(zipStream)) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                Path out = base.resolve(entry.getName()).normalize();
                if (!out.startsWith(base)) {
                    throw new SecurityException("Zip entry escapes extract directory");
                }
                if (!entry.isDirectory()) {
                    try (FileOutputStream fos = new FileOutputStream(out.toFile())) {
                        byte[] buf = new byte[1024];
                        int n;
                        while ((n = zis.read(buf)) > 0) {
                            fos.write(buf, 0, n);
                        }
                    }
                }
                zis.closeEntry();
            }
        }
    }
}
