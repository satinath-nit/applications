package com.example.demo;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;
@RepositoryRestResource(collectionResourceRel = "customers",path = "customers")
public interface CustomersRepo extends JpaRepository<Customers, Integer> {
	

}
