FROM ruby:2.5.8-stretch
RUN echo "deb http://archive.debian.org/debian/ stretch main" > /etc/apt/sources.list \
    && echo "deb http://archive.debian.org/debian-security stretch/updates main" >> /etc/apt/sources.list
RUN apt-get update -qq && apt-get install -y curl && apt-get install -y nodejs && apt-get install -y vim
COPY Gemfile .
RUN bundle install