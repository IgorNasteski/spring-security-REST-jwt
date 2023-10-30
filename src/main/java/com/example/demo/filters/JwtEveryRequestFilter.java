package com.example.demo.filters;

import com.example.demo.service.MyUserDetailService;
import com.example.demo.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtEveryRequestFilter extends OncePerRequestFilter{

    //Ovaj filter ce nam presretati svaki request koji dolazi od strane klijenta(jer extende-ujemo klasu OncePerRequestFilter)
    //cim se klijent uspesno loguje, mi mu pravimo jwt i saljemo mu, taj jwt ocekujemo svaki njegov naredni request
    //mi cemo u metodi doFilterInternal da raspakujemo iz hedera jwt i da proverimo da li je dobar pri svakom klijentovom requestu

    //NOTE: posto presrecemo svaki userov request i vrsimo autentikaciju(proveravamo jwt da li ima koji smo mu slali), moramo ugasiti SESIJU!
    //to radimo u security config klasi dodajuci .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    //zasto to radimo? Spring security kada vrsi autentikaciju(nakon unosa username-a i password-a), ako se user uspesno uloguje, za svaki sledeci request nece morati da
    //vrsi autentikaciju vise jer podatke o ulogovanom useru cuva u security context-u koji se nalazi upravo u sesiji(sesija - vreme od kad se user ulogovao sve dok se ne izloguje)
    //pa zato nece biti potrebe da spring security proverava svaki request usera, jednom ga je proverio(autentifikovao nakon logina) i to je to
    //a posto koristimo jwt, mi gasimo SESIJU, jer cemo samo pri loginu, kada unosi user username i password, mi reci spring security-u(u controller metodi) da uradi autentikaciju
    //tj da proveri da li postoji taj user i da li je uneo dobre kredencijale. Tu proveru/autentikaciju ce imati samo taj put pri loginu, ALI svaki sledeci request koji user
    //bude imao ka bilo kom endpointu nadalje, mi cemo vrsiti opet proveru(kao autentikaciju) ali ne username-a i password-a usera vec da li ima u hederu jwt token koji smo mu slali

    @Autowired
    private MyUserDetailService myUserDetailService;

    @Autowired
    private JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        System.out.println("U FILTERU GDE PROVERAVAM TOKEN OD USERA IZ HEDERA");

        String authorizationHeader = request.getHeader("Authorization");
        System.out.println("AUTHORIZATION HEADER " + authorizationHeader);

        String token = null;
        String username = null;
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            token = authorizationHeader.substring(7);
            username = jwtUtil.extractUsername(token);
        }

        //AKO USER IMA VALIDAN/ODGOVARAJUCI JWT, UZIMAMO UserDetails IZ NASEG MyUserDetailsService I SACUVACEMO GA U SECURITY CONTEXT !!!!
        //          OVO JE KRUCIJALNO DA URADIMO DA BI RADILO, DA BI REKLI SPRING SECURITY-U DA OVAJ AUTENTIFIKOVAN USER IMA VALIDAN JWT KOJI SMO MU SLALI I
        //          DA GA PUSTI DALJE SVAKI REQUEST/ENDPOINT(NARAVNO,SVAKI NJEGOV BUDUCI REQUEST CEMO MU PROVERAVATI JWT)
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = myUserDetailService.loadUserByUsername(username);
            if (jwtUtil.validateToken(token, userDetails)) {//validiramo/proveravamo da li mu je dobar jwt token(da li se username "matches" i da nije jwt expire-ovao)
//!!!!!!!!!U vašem filteru, kada proveravate userov JWT token, morate ručno vršiti proveru autentikacije korisnika, umesto da prepustite Spring Security-u da to uradi automatski.
                //              OVDE TO RADIM, OVO JE KRUCIJALNO,OVO SPRING SECURITY KORISTI ZA UPRAVLJANJE AUTENTIKACIJOM U KONTEKSTU USERNAME-A I PASSWORD-A
                //              OVO SE U SPRING SECURITY-U DESAVA PO DEFAULT-U, ALI POSTO MI PREUZIMAMO KONTROLU, MI OVO MORAMO DA SETUJEMO ALI SAMO POD USLOVOM DA JE USERU VALIDAN JWT
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        filterChain.doFilter(request, response);
    }

//    @Override
//    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
//        System.out.println("U FILTERU GDE PROVERAVAM TOKEN OD USERA IZ HEDERA");
//
//        //jwt ce se nalaziti u hederu(svaki clan hedera je kao key&value) clan/key/jwt se zove "Authorization" a vrednost mu je "Bearer + jwtVrednost"
//        final String authorizationHeader = request.getHeader("Authorization");
//
//        System.out.println("AUTHORIZATION HEADER " + authorizationHeader);
//
//        String username = null;
//        String jwtToken = null;
//
//        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
//            jwtToken = authorizationHeader.substring(7);    //Preskačemo "Bearer "
//            username = jwtUtil.extractUsername(jwtToken);
//            System.out.println("u filteru gde presrecem pri svakom requestu usera. Username: " + username + ", jwt token: " + jwtToken);
//        }
//
//        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
//            UserDetails userDetails = this.myUserDetailService.loadUserByUsername(username);
//
//            if (jwtUtil.validateToken(jwtToken, username)) {    //Ovaj deo koda proverava validnost JWT tokena
//                //ovaj deo mi nije najjasniji, ovo spring boot radi svakako u pozadini, ali posto mi preuzimamo taj deo, moramo da dodamo i ovo
//                //Ovaj korak je neophodan kako bi se omogućio pristup zaštićenim resursima u vašoj aplikaciji. Bez ovog koraka, korisnik ne bi bio pravilno autentifikovan
//                //u Spring Security kontekstu, čime bi mu bilo onemogućeno pristupanje zaštićenim resursima. U suštini, ovo je način kako se ručno postavlja autentifikacija
//                //korisnika na osnovu validnog JWT tokena.
//                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
//                usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
//            }
//        }
//        filterChain.doFilter(request, response);
//    }

}
