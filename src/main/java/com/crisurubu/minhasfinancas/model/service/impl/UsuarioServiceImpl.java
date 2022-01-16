package com.crisurubu.minhasfinancas.model.service.impl;

import java.util.Optional;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.crisurubu.minhasfinancas.model.entities.Usuario;
import com.crisurubu.minhasfinancas.model.exceptions.ErroAutenticacao;
import com.crisurubu.minhasfinancas.model.exceptions.RegraNegocioException;
import com.crisurubu.minhasfinancas.model.repository.UsuarioRepository;
import com.crisurubu.minhasfinancas.model.service.UsuarioService;

@Service
public class UsuarioServiceImpl implements UsuarioService{
	
	
	private UsuarioRepository repository;
	private PasswordEncoder encoder;
	
	
	public UsuarioServiceImpl(UsuarioRepository repository, PasswordEncoder encoder) {
		super();
		this.repository = repository;
		this.encoder = encoder;
	}

	@Override
	public Usuario autenticar(String email, String senha) {
		Optional<Usuario> usuario = repository.findByEmail(email);
		
		if (!usuario.isPresent()) {
			throw new ErroAutenticacao("Usuario não encontrado");
			
		}
		
		boolean senhaBatem = encoder.matches(senha, usuario.get().getSenha());
		if(!senhaBatem) {
			throw new ErroAutenticacao("Senha Invalida.");
		}
		
		return usuario.get();
	}

	@Override
	public Usuario salvarUsuario(Usuario usuario) {
		validarEmail(usuario.getEmail());
		criptografaSenha(usuario);		
		return repository.save(usuario);
	}

	private void criptografaSenha(Usuario usuario) {
		String senha = usuario.getSenha();
		String senhaCriptografada = encoder.encode(senha);
		usuario.setSenha(senhaCriptografada);
	}

	@Override
	public void validarEmail(String email) {
		boolean existe = repository.existsByEmail(email);
		if(existe) {
			throw new RegraNegocioException("Ja existe o email cadastrado..");
		}
		
	}

	@Override
	public Optional<Usuario> obterPorId(Long id) {
		return repository.findById(id);
	}
	

}
