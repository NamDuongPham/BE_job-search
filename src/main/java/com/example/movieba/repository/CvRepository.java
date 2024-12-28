package com.example.movieba.repository;

import com.example.movieba.entities.Cv;
import com.example.movieba.entities.News;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CvRepository extends JpaRepository<Cv,Long>, JpaSpecificationExecutor<Cv> {
//    List<Cv> findAllByNews(News news);

    Optional<Cv> findByNameFile(String nameFile);



    List<Cv> findAllByIdCvIsIn(List<Long> ids );

}
