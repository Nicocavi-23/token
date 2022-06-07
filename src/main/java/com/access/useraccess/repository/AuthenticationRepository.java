package com.access.useraccess.repository;

import com.access.useraccess.entity.Authentication;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AuthenticationRepository extends CrudRepository<Authentication, Long> {

}
