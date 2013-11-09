package br.com.mycompany;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Servlet implementation class LerCertificado
 */
public class LerCertificado extends HttpServlet {
	private static final long serialVersionUID = 1L;

	/**
	 * Default constructor.
	 */
	public LerCertificado() {
		// TODO Auto-generated constructor stub
	}

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse
	 *      response)
	 */
	protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		PrintWriter out = response.getWriter();
		out.println("<html>");
		out.println("<head><title>ServletLerCertificado</title></head>");
		out.println("<body>");
		out.println("<p>Certificado digital:</p>");

		//
		String cipherSuite = (String) request
				.getAttribute("javax.servlet.request.cipher_suite");

		if (cipherSuite != null) {
			java.security.cert.X509Certificate certChain[] = (java.security.cert.X509Certificate[]) request
					.getAttribute("javax.servlet.request.X509Certificate");
			System.out.println("Array size: " + certChain.length); 
			if (certChain != null) {
				for (int i = 0; i < certChain.length; i++) {
					String certInfo = "Client Certificate [" + i + "] = "
							+ certChain[i].toString();
					
					out.println(certInfo);
					System.out.println(certInfo);
					out.println("<h1>ICP-Brasil</h1>");
					out.println(CertAux.getInfo(certChain[i]).replaceAll("/n", "<br/>"));
				}
				
				
			}
		} else {
			out.println("Cliente sem Certificado Digital");
		}

		//
		out.println("</body></html>");
		out.close();
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse
	 *      response)
	 */
	protected void doPost(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		doGet(request, response);
	}

}
