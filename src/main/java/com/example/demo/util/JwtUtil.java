package com.example.demo.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.function.Function;

@Service
public class JwtUtil {      //NOTE: Paketi koji su nazvani kao "util" često sadrže korisne klase, metode ili funkcionalnosti koje se mogu koristiti na različitim mestima u aplikaciji.
                            //Ove klase i metode obično pružaju opštu pomoćnu funkcionalnost koja može biti korisna u različitim delovima koda

    @Value("${my.secret.key}")//izvlacim iz application.properties fajla
    private String SECRET_KEY;
    //private final String SECRET_KEY = "djskaldjgksdwertyuasdewtd3g232k23423rf3g43t43g443g34g43432532tgf";  //mora da bude duzi secret key, ovaj ima 64 karaktera
    private final long EXPIRATION_TIME = 900_000; // 15 minuta

    public String generateToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
                .compact();
    }

    //vadi username usera pomocu tokena(prosledimo token)
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    //proverava da li je jwt koji salje klijent u svakom sledecem requestu isti kao jwt koji smo mu poslali nakon logina
//    public boolean validateToken(String jwtToken, String username) {
//        String extractedUsername = extractUsername(jwtToken);
//        return extractedUsername.equals(username) && !isTokenExpired(jwtToken);
//    }
    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    //vraca boolean, mi prosledimo token a ona nam kaze da li je token istekao
    public boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    //uzima token i prikazuje nam podatke koje smo slali serveru
    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
    }


}
