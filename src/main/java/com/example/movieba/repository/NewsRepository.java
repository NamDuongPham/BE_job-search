package com.example.movieba.repository;

import com.example.movieba.entities.News;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

import java.util.Date;
import java.util.List;
import java.util.Optional;

@Repository
public interface NewsRepository extends JpaRepository<News,Long> , JpaSpecificationExecutor<News> {
    Optional<News> findByTimeNews(Date date);

    List<News> findAllByIdNewIsIn(List<Long> ids );



}
