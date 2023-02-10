package kr.co.linkhub.auth;

import java.util.List;

/**
 * Token Structure. built from TokenBuilder.
 * @author KimSeongjun
 * @see http://www.linkhub.co.kr
 * @version 1.1.0
 */
public class Token {

	private String session_token;
	private String serviceID;
	private String linkID;
	private String usercode;
	private String ipaddress;
	private String expiration;
	private List<String> scope;
	
	/**
	 * Returns session_token string. will be used for BearerToken for API Authoirization.
	 * @return session_token string
	 */
	public String getSession_token() {
		return session_token;
	}
	/**
	 * Returns token's ServiceID 
	 * @return token's ServiceID
	 */
	public String getServiceID() {
		return serviceID;
	}
	/**
	 * Returns token's LinkID
	 * @return token's LinkID
	 */
	public String getLinkID() {
		return linkID;
	}
	/**
	 * Returns token's UserCode
	 * @return token's UserCode
	 */
	public String getUsercode() {
		return usercode;
	}
	/**
	 * Returns token's IPaddress which can be used.
	 * @return token's IPaddress
	 */
	public String getIpaddress() {
		return ipaddress;
	}
	/**
	 * Returns token's Expiration Time which can be used until.
	 * @return token's expiration
	 */
	public String getExpiration() {
		return expiration;
	}
	/**
	 * Return token's scope limit.
	 * @return token's scope
	 */
	public List<String> getScope() {
		return scope;
	}
}
