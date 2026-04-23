package com.example.demo.service;

import java.util.Collections;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.example.demo.entity.CounsellorEntity;
import com.example.demo.repo.CounsellorRepo;
@Service
public class MyUserDetailService implements UserDetailsService{
	@Autowired
	private CounsellorRepo cr;
	@Override
	public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
		CounsellorEntity counsellor=cr.findByCounselloremail(email);
		
		return new User(counsellor.getCounselloremail(),
				counsellor.getPassword(), Collections.emptyList());
	}
;
}
