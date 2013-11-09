package br.com.mycompany;

import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;

import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

/**
 * Classe que, com ajuda da biblioteca Bouncy castle, lê o cpf ou cnpj de dentro
 * de um certificado digital que esteja no padrão do ICP Brasil
 * */
public class CertAux {
	public static final DERObjectIdentifier OID_PESSOA_FISICA_DADOS_TITULAR = new DERObjectIdentifier(
			"2.16.76.1.3.1");
	public static final DERObjectIdentifier OID_PESSOA_JURIDICA_RESPONSAVEL = new DERObjectIdentifier(
			"2.16.76.1.3.2");
	public static final DERObjectIdentifier OID_PESSOA_JURIDICA_CNPJ = new DERObjectIdentifier(
			"2.16.76.1.3.3");
	public static final DERObjectIdentifier OID_PESSOA_JURIDICA_DADOS_RESPONSAVEL = new DERObjectIdentifier(
			"2.16.76.1.3.4");
	public static final DERObjectIdentifier OID_PESSOA_FISICA_ELEITORAL = new DERObjectIdentifier(
			"2.16.76.1.3.5");
	public static final DERObjectIdentifier OID_PESSOA_FISICA_INSS = new DERObjectIdentifier(
			"2.16.76.1.3.6");
	public static final DERObjectIdentifier OID_PESSOA_JURIDICA_INSS = new DERObjectIdentifier(
			"2.16.76.1.3.7");
	public static final DERObjectIdentifier OID_PESSOA_JURIDICA_NOME_EMPRESARIAL = new DERObjectIdentifier(
			"2.16.76.1.3.8");

	@SuppressWarnings("unchecked")
	public static String getInfo(X509Certificate cert) {
		StringBuffer buff = new StringBuffer("");
		try {

			Collection col = X509ExtensionUtil.getSubjectAlternativeNames(cert);

			for (Object obj : col) {

				if (obj instanceof ArrayList) {

					ArrayList lst = (ArrayList) obj;

					Object value = lst.get(1);

					if (value instanceof DERSequence) {

						/**
						 * DER Sequence ObjectIdentifier Tagged DER Octet String
						 */
						DERSequence derSeq = (DERSequence) value;

						DERObjectIdentifier derOid = (DERObjectIdentifier) derSeq
								.getObjectAt(0);
						DERTaggedObject derTagged = (DERTaggedObject) derSeq
								.getObjectAt(1);
						String info = null;

						DERObject derObj = derTagged.getObject();

						if (derObj instanceof DEROctetString) {
							DEROctetString octet = (DEROctetString) derObj;
							info = new String(octet.getOctets());
						} else if (derObj instanceof DERPrintableString) {
							DERPrintableString octet = (DERPrintableString) derObj;
							info = new String(octet.getOctets());
						} else if (derObj instanceof DERUTF8String) {
							DERUTF8String str = (DERUTF8String) derObj;
							info = str.getString();
						}

						if (info != null && !info.isEmpty()) {
							if (derOid.equals(OID_PESSOA_FISICA_DADOS_TITULAR)
									|| derOid
											.equals(OID_PESSOA_JURIDICA_DADOS_RESPONSAVEL)) {
								String nascimento = info.substring(0, 8);

								buff.append("Data Nascimento: "
										+ new SimpleDateFormat("ddMMyyyy")
												.parse(nascimento));
								buff.append("\n");
								String cpf = info.substring(8, 19);
								buff.append("CPF: " + cpf);
								String nis = info.substring(19, 30);
								buff.append("\n");
								buff.append("NIS: " + nis);
								buff.append("\n");
								String rg = info.substring(30, 45);
								buff.append("RG: " + rg);
								buff.append("\n");
								if (!rg.equals("000000000000000")) {
									String ufExp = info.substring(45, 50);
									buff.append("Orgão Expedidor: " + ufExp);
									buff.append("\n");
								}
							} else if (derOid.equals(OID_PESSOA_FISICA_INSS)) {
								String inss = info.substring(0, 12);
								buff.append("INSS: " + inss);
								buff.append("\n");
							} else if (derOid
									.equals(OID_PESSOA_FISICA_ELEITORAL)) {
								String titulo = info.substring(0, 12);
								buff.append("Titulo de Eleitor: " + titulo);
								buff.append("\n");
								String zona = info.substring(12, 15);
								buff.append("Zona Eleitoral: " + zona);
								buff.append("\n");
								String secao = info.substring(15, 19);
								buff.append("Seção: " + secao);
								buff.append("\n");
								if (!titulo.equals("000000000000")) {
									String municipio = info.substring(19, 41);
									buff.append("Municipio: " + municipio);
									buff.append("\n");
								}
							} else if (derOid
									.equals(OID_PESSOA_JURIDICA_RESPONSAVEL)) {
								buff.append("Responsavél: " + info);
								buff.append("\n");
							} else if (derOid.equals(OID_PESSOA_JURIDICA_CNPJ)) {
								buff.append("CNPJ: " + info);
								buff.append("\n");
							} else if (derOid.equals(OID_PESSOA_JURIDICA_INSS)) {
								buff.append("INSS: " + info);
								buff.append("\n");
							} else if (derOid
									.equals(OID_PESSOA_JURIDICA_NOME_EMPRESARIAL)) {
								buff.append("NOME: " + info);
								buff.append("\n");
							}
						}
					} else {
						buff.append("Extra: " + value);
					}
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return buff.toString();
	}

	// public static void main(String[] args) {
	//
	// FileInputStream fr;
	// try {
	// fr = new FileInputStream("c://ju.cer");
	// CertificateFactory cf = CertificateFactory.getInstance("X.509");
	// java.security.cert.X509Certificate c = (X509Certificate) cf
	// .generateCertificate(fr);
	//			
	// System.out.println(getInfo(c));
	// } catch (Exception e) {
	// // TODO Auto-generated catch block
	// e.printStackTrace();
	// }
	//
	// }

}