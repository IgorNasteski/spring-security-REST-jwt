package com.example.demo.security;

import com.example.demo.filters.JwtEveryRequestFilter;
import com.example.demo.service.MyUserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity//(debug = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private MyUserDetailService myUserDetailService;

    @Autowired
    private JwtEveryRequestFilter jwtEveryRequestFilter;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(myUserDetailService).passwordEncoder(getPasswordEncoder());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/users/authenticate").permitAll()
                .anyRequest().authenticated()
                .and()

                //NOTE: posto presrecemo svaki userov request i vrsimo autentikaciju(proveravamo jwt da li ima koji smo mu slali), moramo ugasiti SESIJU!
                //to radimo u security config klasi dodajuci .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
                //zasto to radimo? Spring security kada vrsi autentikaciju(nakon unosa username-a i password-a), ako se user uspesno uloguje, za svaki sledeci request nece morati da
                //vrsi autentikaciju vise jer podatke o ulogovanom useru cuva u security context-u koji se nalazi upravo u sesiji(sesija - vreme od kad se user ulogovao sve dok se ne izloguje)
                //pa zato nece biti potrebe da spring security proverava svaki request usera, jednom ga je proverio(autentifikovao nakon logina) i to je to
                //a posto koristimo jwt, mi gasimo SESIJU, jer cemo samo pri loginu, kada unosi user username i password, mi reci spring security-u(u controller metodi) da uradi autentikaciju
                //tj da proveri da li postoji taj user i da li je uneo dobre kredencijale. Tu proveru/autentikaciju ce imati samo taj put pri loginu, ALI svaki sledeci request koji user
                //bude imao ka bilo kom endpointu nadalje, mi cemo vrsiti opet proveru(kao autentikaciju) ali ne username-a i password-a usera vec da li ima u hederu jwt token koji smo mu slali

                //kazemo spring security-u da ne upravlja sesijama / da ne kreira sesiju
                //jer ceo razlog zasto radimo JWT je da bude STATELESS
                //JER KADA IMAMO SESIJU, DOVOLJNO JE DA SE JEDNOM AUTENTIFIKUJEMO UNOSOM USERNAME-A I PASSWORD-A, PA CE NAS SVAKI SLEDECI REQUEST PO NEKIM NASIM ENDPOINTIMA
                //PUSTATI BEZ PROVERE/AUTENTIKACIJE USERNAME-A I PASSWORD-A JER SMO SE NA POCETKU AUTENTIFIKOVALI KAD SMO SE LOGOVALI.
                //A SADA, KADA SMO SESIJU ISKLJUCILI, NARAVNO, RADICE SE AUTENTIFIKACIJA PRI LOGINU(GDE USERU SALJEMO U HEDER NAS JWT KOJI POSLE OCEKUJEMO PRI SVAKOM REQUESTU)
                //ALI CE I NADALJE SVAKI REQUEST MORATI DA SE AUTENTIFIKUJE U NEKU RUKU, TJ PROVARACEMO SVAKI REQUEST, PA AKO U SVAKOM REQUESTU IMAMO
                //U HEDERU JWT TOKEN("Authorization" vrednost "Bearer fr44rrr...") ONDA CE NAS PUSTITI DA KORISTIMO TAJ ENDPOINT
                //NECE IMATI SESIJU NA SERVERU - GLEDACE SVAKI REQUEST, NECE SADA IMATI MEMORIJU ZA PREDJASNJA DESAVANJA(SESIJA)
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

                //posto spring security sada nece kreirati sesiju(jer smo mu mi rekli), trebace nam nesto sto radi za svaki request, proverava ga i setuje security context svaki put
                //tu na scenu dolazi nas filter, on ce raditi pri svakom requestu usera i pri svakom userovom requestu ce setovati security context(pogledati u mom filteru taj deo)
                http.addFilterBefore(jwtEveryRequestFilter, UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    public PasswordEncoder getPasswordEncoder(){
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

}
