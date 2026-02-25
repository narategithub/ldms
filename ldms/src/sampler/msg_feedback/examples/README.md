Feedback Channel
================


```txt

setup:

   app1 -->----- samp1 ───────<───┐
                   '---->--------.│
                                 agg11 ─────<───────┐
                   .---->--------'│  '--->---------.│
   app2 -->----- samp2 ───────<───┘                |│
                                                   agg21 ---<------ analyser
                 samp3 ───────<───┐                |│
                   '---->--------.│  .--->---------'│
                                 agg12 ─────<───────┘
                   .---->--------'│
                 samp4 ───────<───┘

 ──── The prdcr connection.
 ---- The msg_chan connection.

 The arrow in this diagram indicates who initates the connection (initatior >
 passive side) and does not indicate the direction of the data flow.

 agg21 subscribes to 'app' tags over [agg21──agg11] connection.
       It does NOT subscribe to 'feedback_cmd' b/c agg21 does not load the
       msg_feedback plugin.

 agg11 loads `msg_feedback` plugin, which creates [agg11---agg21] connection.
 agg11 subscribes to 'feedback_cmd' and 'app' tags over [agg11──samp1] conn.
 agg11 subscribes to 'feedback_cmd' and 'app' tags over [agg11──samp2] conn.

 agg11 loads `msg_feedback` plugin, which creates [agg12---agg21] connection.
 agg12 subscribes to 'feedback_cmd' and 'app' tags over [agg12──samp3] conn.
 agg12 subscribes to 'feedback_cmd' and 'app' tags over [agg12──samp4] conn.

 analyser subscribes to 'app' tag over [analyser---agg21] conn that it created.
 The application (app1, app2) will publish the data for analysis with 'app' tag.

 app1 subscribe to 'foo' tag over [app1--samp1] connection to receive results
 from the analyser.

 'feedback_cmd' messages goes from app to agg21 direction
 'app' messages goes from app to analyser direction

 'foo' messages goes from analyser to samplers direction.


```

```txt

1) app1 publishes on 'feedback_cmd' with content 'sub:foo' so that the
   msg_feedback plugins receiving this will subscribe 'foo' tag over their
   channel.

   fb for feedback_cmd

    fb:'sub:foo' >      fb:'sub:foo' >
   app1 -------- samp1 ───────────┐
         (foo)     '-------------.│
                        (foo)    agg11 ─────────────┐
                                  │  |              │
                   .-------------'│  '-------------.│
   app2 -------- samp2 ───────────┘       (foo)    |│      (app )
                                                   agg21 ---------- analyser
                 samp3 ───────────┐                |│             (sub to app)
                   '-------------.│  .-------------'│
                                 agg12 ─────────────┘
                   .-------------'│
                 samp4 ───────────┘

  samp1 recv 'sub:foo' over [app1---samp1] connection with 'feedback_cmd' tag.
  The msg_feedback plugin on samp1 receives it and subscribe to 'foo' on
  [samp1---agg11] connection/channel that the plugin created.

  'feedback_cmd' 'sub:foo' message got propagated to agg11 over [samp1──agg11]
  connection because agg11 prdcr_subscribe to 'feedback_cmd'.

  agg11 recv 'sub:foo' over [samp1──agg11] connection with 'feedback_cmd' tag.
  The msg_feedback plugin on agg11 receives it and subscribe to 'foo' on
  [agg11---agg21] connection/channel that the plugin created.

  The message with 'feedback_cmd' tag does not propagate to agg21 because agg21
  does not subscribe to it.

  The analyser subscribed to the pre-determined 'app' tag over the
  [agg21---analyser] channel that he created.

  Note that app1 already subscribed to 'foo' over [app1--samp1] connection for
  receiving results back from the analyser when it started.

```

```txt

2) app1 publishes application information targeting analyser by publishing
   with the 'app' tag. In this case, app1 publishes 'foo:hello' with 'app' tag
   on [app1---samp1] connection created by app1.


      app:'foo:hello' >   app:'foo:hello' >
   app1 -------- samp1 ───────────┐
                   '-------------.│     app:'foo:hello' >
                       (foo)     agg11 ─────────────┐
                                  │  |              │
                   .-------------'│  '-------------.│
   app2 -------- samp2 ───────────┘      (foo)     |│    app:'foo:hello' >
                                                   agg21 ---------- analyser
                 samp3 ───────────┐                |│
                   '-------------.│  .-------------'│
                                 agg12 ─────────────┘
                   .-------------'│
                 samp4 ───────────┘


   samp1 process receives 'foo:hello' message with 'app' tag but no one on samp1
   subscribed to it. So, samp1 does not process 'foo:hello' message. However,
   since agg11 subscribe to 'app' on [agg11──samp1] connection, ldms_msg on
   samp1 service propagates 'foo:hello' to agg11 over [agg11──samp1]
   connection.

   agg11 process receives 'foo:hello' message with 'app' tag but no one on agg11
   subscribed to it. So, agg11 does not process 'foo:hello' message. However,
   since agg21 subscribe to 'app' on [agg21──agg11] connection, ldms_msg on
   agg11 service propagates 'foo:hello' to agg21 over [agg21──agg11]
   connection.

   agg21 process receives 'foo:hello' message with 'app' tag but no one on agg21
   subscribed to it. So, agg21 does not process 'foo:hello' message. However,
   since analyser subscribe to 'app' on [analyser--agg21] connection, ldms_msg
   on agg21 service propagates 'foo:hello' to analyser over [analyser--agg21]
   connection.

   Finally analyser receives 'foo:hello' message with 'app' tag and process it.
   The analyser extract 'foo' from the message and understands that it will
   publish the result back to app using 'foo' tag.

```

```txt
3) analyser publishes 'ACK: foo:hello' message with tag 'foo' back to agg21 over
   [analyser--agg21] connection.

      < foo:'ACK..'
   app1 -------- samp1 ───────────┐
                   | < foo:'ACK..'│
                   '-------------.│
                       (foo)     agg11 ─────────────┐
                                  │  | < foo:'ACK..'│
                   .-------------'│  '-------------.│
   app2 -------- samp2 ───────────┘      (foo)     |│    < foo:'ACK: foo:hello'
                                                   agg21 ---------- analyser
                 samp3 ───────────┐                |│
                   '-------------.│  .-------------'│
                                 agg12 ─────────────┘
                   .-------------'│
                 samp4 ───────────┘

   agg21 receives 'ACK: foo:hello' message with 'foo' tag but no one on agg21
   subscribed to it. So, agg21 does not process the message. However, since
   agg11 subscribed to 'foo' on [agg11--agg21] connection, ldms_msg on agg21
   service propagates 'ACK: foo:hello' with 'foo' tag to agg11 over
   [agg11--agg21] connection.

   agg11 receives 'ACK: foo:hello' message with 'foo' tag but no one on agg11
   subscribed to it. So, agg11 does not process the message. However, since
   samp1 subscribed to 'foo' on [samp1--agg11] connection, ldms_msg on agg11
   service propagates 'ACK: foo:hello' with 'foo' tag to samp1 over
   [samp1--agg11] connection.

   samp1 receives 'ACK: foo:hello' message with 'foo' tag but no one on samp1
   subscribed to it. So, samp1 does not process the message. However, since
   app1 subscribed to 'foo' on [app1--samp1] connection, ldms_msg on samp1
   service propagates 'ACK: foo:hello' with 'foo' tag to app1 over
   [app1--samp1] connection.

   Finally app1 receives the 'ACK: foo:hello' message with 'foo' tag over
   [app1--samp1] connection and prints it out.

```

```txt
4) Before app1 exits, it publishes 'unsub:foo' with 'feedback_cmd' tag to samp1
   over [app1--samp1] connection. This is so that the ldmsds in the chain
   receives an feedback *unsubscription* request and unsubscribed themselves
   from 'foo' tag over [samp1--agg11] connection and [agg11--agg21] connection
   respectively. The 'unsub:foo' with 'feedback_cmd' tag propagates the same way
   that 'sub:foo' did in 2) and the setup went back to the original state.

   fb for feedback_cmd

                        (app,fb)
   app1 -------- samp1 ───────────┐
          (foo)    '-------------.│      (app)
                                 agg11 ─────────────┐
                   .-------------'│  '-------------.│
   app2 -------- samp2 ───────────┘                |│
                        (app,fb)                   |│
                                                   agg21 ---------- analyser
                        (app,fb)                   |│      (app)
                 samp3 ───────────┐                |│
                   '-------------.│  .-------------'│
                                 agg12 ─────────────┘
                   .-------------'│      (app)
                 samp4 ───────────┘
                        (app,fb)
```
