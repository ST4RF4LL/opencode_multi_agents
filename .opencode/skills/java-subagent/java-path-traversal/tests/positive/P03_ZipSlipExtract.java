import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class P03_ZipSlipExtract {
    public void vulnerable(InputStream zipStream, File destDir) throws Exception {
        try (ZipInputStream zis = new ZipInputStream(zipStream)) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                File out = new File(destDir, entry.getName());
                if (!entry.isDirectory()) {
                    out.getParentFile().mkdirs();
                    try (FileOutputStream fos = new FileOutputStream(out)) {
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
