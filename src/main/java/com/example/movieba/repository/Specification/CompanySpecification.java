package com.example.movieba.repository.Specification;

import com.example.movieba.entities.Company;
import org.springframework.data.jpa.domain.Specification;

public class CompanySpecification {
    public static Specification<Company> filterCom(Long newId){
        return Specification.where(withNewId(newId));
    }

    public static Specification<Company> withNewId(Long newId){
        if (newId == 0 || newId == null) return null;
        return (root, query, criteriaBuilder) -> criteriaBuilder.like(root.get("listNews"),"%" +newId +"%");
    }
}
