/*
 * use itext to decrypt the pdf
 */
import com.itextpdf.io.font.FontConstants;
import com.itextpdf.kernel.crypto.CryptoUtil;
import com.itextpdf.kernel.PdfException;
import com.itextpdf.kernel.crypto.BadPasswordException;
import com.itextpdf.kernel.font.PdfFontFactory;
import com.itextpdf.kernel.utils.CompareTool;
import com.itextpdf.kernel.xmp.XMPException;
import com.itextpdf.test.ExtendedITextTest;
import com.itextpdf.test.ITextTest;
import com.itextpdf.test.annotations.type.IntegrationTest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfPage;
import com.itextpdf.kernel.pdf.ReaderProperties;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class PdfEncryptionTest {

    public static Certificate getPublicCertificate(String path) throws IOException, CertificateException {
        FileInputStream is = new FileInputStream(path);
        return CryptoUtil.readPublicCertificate(is);
    }

    public static PrivateKey getPrivateKey(String filename, String password) throws GeneralSecurityException, IOException {
        return CryptoUtil.readPrivateKeyFromPKCS12KeyStore(new FileInputStream(filename), "sandbox", password.toCharArray());
    }

    public static void main(String [] args) throws IOException, CertificateException, GeneralSecurityException
    {
        Security.addProvider(new BouncyCastleProvider());
        String filename = args[0];
        Certificate certificate = getPublicCertificate(args[1]);
        PrivateKey privkey = getPrivateKey(args[1], args[2]);

        PdfReader reader = new PdfReader(filename, new ReaderProperties().setPublicKeySecurityParams(certificate, privkey, "BC", null));
        PdfDocument document = new PdfDocument(reader);
        PdfPage page = document.getPage(1);

        System.out.println("content = " + new String(page.getStreamBytes(0)));
        System.out.println("author = " + document.getDocumentInfo().getAuthor());
        System.out.println("creator = " + document.getDocumentInfo().getCreator());

        document.close();

    }
}

