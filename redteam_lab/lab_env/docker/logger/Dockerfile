FROM fluent/fluentd:v1.16-1

COPY fluent.conf /fluentd/etc/
RUN gem install fluent-plugin-elasticsearch
EXPOSE 24224
CMD ["fluentd"]
