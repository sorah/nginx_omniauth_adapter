FROM quay.io/sorah/rbenv:2.2
MAINTAINER sorah

RUN mkdir -p /app

ADD Gemfile* /tmp/
ADD nginx_omniauth_adapter.gemspec /tmp/
RUN mkdir -p /tmp/lib/nginx_omniauth_adapter
ADD lib/nginx_omniauth_adapter/version.rb /tmp/lib/nginx_omniauth_adapter/version.rb
RUN cd /tmp && bundle install -j4 --path vendor/bundle --without 'development test'

WORKDIR /app
ADD . /app
RUN cp -a /tmp/.bundle /tmp/vendor /app/
RUN rm -f /app/.ruby-version

EXPOSE 8080
ENV RACK_ENV=production
CMD ["bundle", "exec", "rackup", "-p", "8080", "-o", "0.0.0.0", "config.ru"]
