package com.access.useraccess.entity;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;

@Entity
@Table(name ="credentials")
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class Authentication {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name="id")
    private Long id;

    @Column(name="token")
    private String token;

    @Column(name="id_user")
    private Long id_user;
}
