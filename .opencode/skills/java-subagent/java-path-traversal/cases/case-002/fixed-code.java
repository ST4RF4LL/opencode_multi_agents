import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class ArchiveExtractService {
    public void extract(InputStream zipStream, Path destDir) throws Exception {
        Path base = destDir.toAbsolutePath().normalize();
        try (ZipInputStream zis = new ZipInputStream(zipStream)) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                Path out = base.resolve(entry.getName()).normalize();
                if (!out.startsWith(base)) {
                    throw new SecurityException("Zip entry escapes extract directory: " + entry.getName());
                }
                if (entry.isDirectory()) {
                    out.toFile().mkdirs();
                } else {
                    File parent = out.toFile().getParentFile();
                    if (parent != null) {
                        parent.mkdirs();
                    }
                    try (FileOutputStream fos = new FileOutputStream(out.toFile())) {
                        byte[] buf = new byte[4096];
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
