package com.nit.hari.util;

import java.util.Base64;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JwtUtil {

	@Value("${app.secret}")
	private String secret;
	
	//6. Validate username in token and DataBase Username and Token ExpDate
	public boolean validateToken(String token,String username) {
		String tokenUserName = getSubject(token);
		return (username.equals(tokenUserName) && !isTokenExp(token));
	}
	
	//5. Validate Expire Date
	public boolean isTokenExp(String token) {
		Date expDate = getExpirationDate(token);
		return expDate.before(new Date(System.currentTimeMillis()));
	}
	
	// 4. Read Subject/Username
	public String getSubject(String token) {
		return getClaims(token).getSubject();
	}
	
	// 3. Read Expiration Date
	public Date getExpirationDate(String token) {
		return getClaims(token).getExpiration();
	}
	
	
	// 2. Read Token
	public Claims getClaims(String token) {
		
		return Jwts.parser()
				.setSigningKey(Base64.getEncoder().encode(secret.getBytes()))
				.parseClaimsJws(token)
				.getBody();
	}
	
	// 1. Generate Token
	public String generateToken(String subject) {
		
		return Jwts.builder()
				.setSubject(subject)
				.setIssuer("PalnatiHari")
				.setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis()+TimeUnit.MINUTES.toMillis(15)))
				.signWith(SignatureAlgorithm.HS512, Base64.getEncoder().encode(secret.getBytes()))
				.compact();
	} 
}
