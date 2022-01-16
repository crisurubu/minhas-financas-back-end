package com.crisurubu.minhasfinancas.api;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import com.crisurubu.minhasfinancas.model.service.JwtService;
import com.crisurubu.minhasfinancas.model.service.impl.SecurityUserDetailservice;

public class JwtTokenFilter extends OncePerRequestFilter {
	
	private JwtService jwtService;
	private SecurityUserDetailservice userDetailService;

	public JwtTokenFilter(JwtService jwtService, SecurityUserDetailservice userDetailService) {
		this.jwtService = jwtService;
		this.userDetailService = userDetailService;
		
		
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		String authorization = request.getHeader("Authorization");
		
		if(authorization != null && authorization.startsWith("Bearer")) {
			String token = authorization.split(" ")[1];
			boolean isTokenValid = jwtService.isTokenValido(token);
			
			if(isTokenValid) {
				String login = jwtService.obterLoginUsuario(token);
				UserDetails usuarioAutenticado = userDetailService.loadUserByUsername(login);
				UsernamePasswordAuthenticationToken user = 
						new UsernamePasswordAuthenticationToken(usuarioAutenticado, null, usuarioAutenticado.getAuthorities());
				
				
				user.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				SecurityContextHolder.getContext().setAuthentication(user);
				
				
			}
		}
		
		filterChain.doFilter(request, response);
	}

}
