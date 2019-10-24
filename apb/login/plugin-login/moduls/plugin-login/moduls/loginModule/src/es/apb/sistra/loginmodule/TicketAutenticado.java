package es.apb.sistra.loginmodule;

import java.util.Date;

public class TicketAutenticado {

    private Date fechaLogin;
    private ApbPrincipal principalAut;
    
	/**
	 * @return the fechaLogin
	 */
	public Date getFechaLogin() {
		return fechaLogin;
	}
	/**
	 * @param fechaLogin the fechaLogin to set
	 */
	public void setFechaLogin(Date fechaLogin) {
		this.fechaLogin = fechaLogin;
	}
	/**
	 * @return the principalAut
	 */
	public ApbPrincipal getPrincipalAut() {
		return principalAut;
	}
	/**
	 * @param principalAut the principalAut to set
	 */
	public void setPrincipalAut(ApbPrincipal principalAut) {
		this.principalAut = principalAut;
	}

}
