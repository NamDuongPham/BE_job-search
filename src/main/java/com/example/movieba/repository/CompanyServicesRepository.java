package com.example.movieba.repository;

import com.example.movieba.entities.Company;
import com.example.movieba.entities.CompanyServices;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface CompanyServicesRepository extends JpaRepository<CompanyServices,Long> {
    List<CompanyServices> findByCompanySer(Company company);
}
