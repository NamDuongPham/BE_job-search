package com.example.movieba.repository.Specification;

import com.example.movieba.entities.News;
import org.springframework.data.jpa.domain.Specification;

public class NewSpecification {
    public static Specification<News> filterAll(Long idCv){
        return Specification.where(withCvId(idCv));
    }

    public static Specification<News> withCvId(Long cv_id){
        if (cv_id == 0 || cv_id == null) return null;
        return (root, query, criteriaBuilder) -> criteriaBuilder.like(root.get("listCV"),"%:" +cv_id +",%");
    }

}
