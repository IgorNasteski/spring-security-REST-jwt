package com.example.demo.controller;

import com.example.demo.msg_request_response_entity.UserAuthenticateLoginRequest;
import com.example.demo.msg_request_response_entity.UserAuthenticateLoginResponse;
import com.example.demo.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/users")
public class LoginController {

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private AuthenticationManager authenticationManager;//da bi ovaj bean koristio ovde(za autentifikaciju usera) moram da ga napravim(override-ujem) u security config klasi.
                                                        //samo obican override metode, cisto da bude dostupan ovde ovaj primerak AuthenticationManagera

    //dodje mu kao login ovaj endpoint, mogao sam da ga nazovem /login, ali kao da bude smisljeniji naziv jer se na loginu ovde autentikuje user i salje mu se jwt u heder
    //moram ovaj endpoint u security config klasi da dozvolim svim userima da pristupe, jer se ovde radi autentifikacija i pakovanje jwt-a nakon uspesnog logina/uspesne autentikacije
    //user ce morati da bude autentifikovan(ovde) da bi bilo kom drugom endpointu zeleo da pristupi
    @PostMapping("/authenticate")
    public ResponseEntity createAuthenticationToken(@RequestBody UserAuthenticateLoginRequest userAuthenticateLoginRequest) throws Exception {
        try {
            //posto se loginujemo preko postmana, saljemo username i password, prihvatamo ga ovde. Ovaj red ispod - kazemo springu da nam uradi autentikaciju(da proveri kredencijale)
            //pa ako je dobro uneo pustaj ga dalje, ako nije ne pustaj ga dalje, vec baci execption(zato cemo staviti u try/catch blok)
            //spring security ovo radi automatski kada mu prepustimo da radi autentikaciju(ali posto sam mu rekao da svaki request mora biti autentikovan .anyRequest().authenticated()
            //to znaci da mi preuzimamo/kao da override-ujemo spring security autentikaciju, pa moramo da dodamo ovaj red ispod da bi rekli spring security-u da izvrsi autentikaciju
            //mi u principu hocemo da ako je user autentikovan(ako je uneo ispravne kredencijale) da mu mi spakujemo jwt i posaljemo u heder(pa pri svakom requestu njegovom proveravamo
            //da li ima u hederu taj jwt)
            //a posto spring security prvo mora da autentikuje usera, mi cemo staviti ovaj red ispod koji upravo to radi - autentifikuje usera! pa ako je ovaj red ispod uspesno izvren,
            //a bice uspesno izvrsen ako je user postojec i ako je uneo dobre kredencijale, onda ce se nastaviti da se izvrsava kod ispod a tamo cemo mi sada uraditi ono sto smo hteli,
            //kreiracemo jwt token i proslediti useru u heder
            //ako se nije dobro ulogovao user, ako ne postoji ili je uneo pogresne kredencijale, uci cemo u catch() blok i baciti error, nece se nijedna vise linija koda ispod izvrsavati
            //necemo ni kreirati ni pakovati token, ovde ce se zavrsiti
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(userAuthenticateLoginRequest.getUsername(), userAuthenticateLoginRequest.getPassword()));
        }catch (BadCredentialsException e){
            throw new Exception("Incorrect username or password ", e);
            //ako nije uneo dobro kredencijale ili ako taj user ne postoji, ovde se baca exception i dobice 403 forbidden, prekida se sve ispod
        }

        //final UserDetails userDetails = myUserDetailService.loadUserByUsername(userAuthenticateLoginRequest.getUsername());
        //final String jwt = jwtUtil.generateToken(userDetails.getUsername());
        final String jwt = jwtUtil.generateToken(userAuthenticateLoginRequest.getUsername());

        return ResponseEntity.ok(new UserAuthenticateLoginResponse(jwt));
    }


            //PRIMER, KAKO CEMO SADA IZ POSTMANA VRSITI LOGIN I POSLE NPR NEKI DRUGI OBICAN ENPOINT U NASOJ APLIKACIJI:
    /*  u postmanu, Post request : http://localhost:8080/users/authenticate     (USEROV LOGIN NA POCETKU)
        body request
    {
        "username" : "jordan10",
        "password" : "jordan10"
    }

        response dobijemo:
        {
            "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJqb3JkYW4xMCIsImlhdCI6MTY5ODUxOTMxMSwiZXhwIjoxNjk4NTIwMjExfQ.JK2gvKWTOD6PQk7sCkCRsCS_avPy597tG_HWKZVH1BA"
        }

        Posle mozemo ici na drugi neki random nas endpoint, npr neki endpoint metode iz HelloController-a. Primer:
        u postmanu, Get request : http://localhost:8080/hello/afterLogin
        ****sada u hederu moramo da dodamo parametar    Authorization       vrednost npr: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJqb3JkYW4xMCIsImlhdCI6MTY5ODUxOTMxMSwiZXhwIjoxNjk4NTIwMjExfQ.JK2gvKWTOD6PQk7sCkCRsCS_avPy597tG_HWKZVH1BA
        response body dobijemo:
        Welcome, home page

        ********svaki sledeci userov request nadalje ce morati u hederu da ima nas jwt koji smo mu dali posle logina
    * */



}