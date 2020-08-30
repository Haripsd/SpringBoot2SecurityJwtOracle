package com.nit.hari.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.nit.hari.util.JwtUtil;

@Component
public class SecurityFilter extends OncePerRequestFilter {

	@Autowired
	private JwtUtil jwtUtil;
	
	@Autowired
	private UserDetailsService userDetailsService;
	
	@Override
	protected void doFilterInternal(HttpServletRequest request,
			HttpServletResponse response, 
			FilterChain filterChain) throws ServletException, IOException 
	{
		String token = request.getHeader("Authorization");
		
		if(token!=null) {
			// do Validation 
			String username = jwtUtil.getSubject(token);
			// Username should not be empty and Security context object must be empty
			
			if(username!=null && SecurityContextHolder.getContext()
					.getAuthentication() == null) {
				UserDetails user = userDetailsService.loadUserByUsername(username);
				// Validating Token Double Cross Verification
				boolean isValid = jwtUtil.validateToken(token, user.getUsername());
				if(isValid) {
					UsernamePasswordAuthenticationToken authToken =
							new UsernamePasswordAuthenticationToken(username,
									user.getPassword(),
									user.getAuthorities());
					
					authToken.setDetails(new WebAuthenticationDetailsSource()
							.buildDetails(request));
					//Final Object Stored in Security Context Object With un,pwd
					SecurityContextHolder.getContext().setAuthentication(authToken);
				}
			}
		}
		filterChain.doFilter(request, response);
	}

}
