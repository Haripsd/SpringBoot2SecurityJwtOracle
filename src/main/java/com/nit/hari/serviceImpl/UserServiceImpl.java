package com.nit.hari.serviceImpl;

import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.nit.hari.model.User;
import com.nit.hari.repo.UserRepository;
import com.nit.hari.service.IUserService;

@Service
public class UserServiceImpl implements IUserService,UserDetailsService {

	@Autowired
	private UserRepository userRepo;
	
	@Autowired
	private BCryptPasswordEncoder pwdEncoder;
	
	// Save User
	@Override
	public Integer saveUser(User user) {
		// Encode Password
		user.setPassword(pwdEncoder.encode(user.getPassword()));
		return userRepo.save(user).getId();
	}
	
	//get User By UserName
	@Override
	public Optional<User> findByUsername(String username) {
		return userRepo.findByUsername(username);
	}
	
	//----------------------------------------------------------//
	@SuppressWarnings("unused")
	@Override
	public UserDetails loadUserByUsername(String username) 
			throws UsernameNotFoundException {
		Optional<User> optuser = findByUsername(username);
		User user = optuser.get();
		if(optuser == null) {
			throw new UsernameNotFoundException("User not Exist!");
		}
		return new org.springframework.security.core.userdetails.User(
				username,
				user.getPassword(), 
				user.getRoles().stream()
				.map(role -> new SimpleGrantedAuthority(role))
				.collect(Collectors.toList()));
		
	}

}
