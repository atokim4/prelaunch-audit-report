import { BadRequestException, Controller, Headers, Post, Req, type RawBodyRequest } from "@nestjs/common";
import type { Request } from "express";
import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY ?? "");

@Controller("api/payments")
export class PaymentsController {
  @Post("webhook")
  webhook(@Req() req: RawBodyRequest<Request>, @Headers("stripe-signature") sig: string) {
    const rawBody = req.rawBody;
    if (!rawBody) throw new BadRequestException("rawBody not found");
    const event = stripe.webhooks.constructEvent(rawBody, sig, process.env.STRIPE_WEBHOOK_SECRET ?? "");
    if (event.type === "checkout.session.completed") {
      // activate the subscription
    }
    return { received: true };
  }
}
