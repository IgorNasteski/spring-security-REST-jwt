package com.example.demo.service;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class MyUserDetailService implements UserDetailsService{


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //radi vezbe cu hardkodovati usera, mogli smo dodati i iz baze usera
        List<GrantedAuthority> authorities = new ArrayList<>();
        SimpleGrantedAuthority roleAdmin = new SimpleGrantedAuthority("ADMIN");
        SimpleGrantedAuthority roleUser = new SimpleGrantedAuthority("USER");
        authorities.add(roleAdmin);
        authorities.add(roleUser);
        UserDetails user = User.withUsername("jordan10").password("jordan10").authorities(authorities).build();
        return user;
    }
}
