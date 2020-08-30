package com.nit.hari.service;

import java.util.Optional;

import com.nit.hari.model.User;

public interface IUserService {
 
	Integer saveUser(User user);
	
	Optional<User> findByUsername(String username);
}
