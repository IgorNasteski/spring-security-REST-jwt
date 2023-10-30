package com.example.demo.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtUtilOLD {

    //ovu klasu smo vrv dobili od jwt api-a(mozda ima i na netu, ne verujem da ljudi ovo sami kucaju/prave_
    //ova klasa sluzi za generisanje tokena, validiranje tokena, raspakovanje username-a, proveru kada token expire-uje

    //kreiranje tokena se radi u metodi generateToken(prosledimo userDetails)
    //a ova metoda u sebi dalje koristi/poziva metodu createToken(iz userDetailsa izvlacimo sta treba)
    // POJASNJENJE :
   /*private String createToken(Map<String, Object> claims, String subject) {
        //                              empty              username             trenutni datum
        return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))                              10 sati od sad
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY).compact();                                              prosledjujemo secret key
    }*/

    //metoda validateToken(jwt, userDetails) nam proverava da li je jwt koji salje klijent u svakom sledecem requestu isti kao jwt koji smo mu poslali nakon logina
    //metoda extractClaim() koja uzima token i prikazuje nam podatke koje smo slali serveru
    //metoda extractUsername(token) nam vadi username usera pomocu tokena(prosledimo token)
    //metoda isTokenExpired vraca boolean, mi prosledimo token a ona nam kaze da li je token istekao

   //secret key ne treba cuvati ovde, najbolje na nekom sigurnom mestu
    private String SECRET_KEY = "secret";//mora da bude duzi secret key, ovaj ima 64 karaktera

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }
    private Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, userDetails.getUsername());
    }

    private String createToken(Map<String, Object> claims, String subject) {

        return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY).compact();
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

}
