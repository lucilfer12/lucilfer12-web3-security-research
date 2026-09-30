impl Chain {
    fn validate_header(&self, block: &Block, prev_hash: CryptoHash, prev_gas_price: Balance) -> Result<(), Error> {
        self.validate_header_common(block)?;

        if block.header().random_value() != &hash(block.vrf_value().0.as_ref()) {
            return Err(Error::InvalidRandomnessBeaconOutput);
        }

        let res = block.validate_with(|block| {
            Chain::validate_block_impl(self.runtime_adapter.as_ref(), &self.genesis, block)
                .map(|_| true)
        });
        if let Err(e) = res {
            byzantine_assert!(false);
            return Err(e);
        }

        let protocol_version =
            self.runtime_adapter.get_epoch_protocol_version(block.header().epoch_id())?;
        if !block.verify_gas_price(
            prev_gas_price,
            self.block_economics_config.min_gas_price(protocol_version),
            self.block_economics_config.max_gas_price(protocol_version),
            self.block_economics_config.gas_price_adjustment_rate(protocol_version),
        ) {
            byzantine_assert!(false);
            return Err(Error::InvalidGasPrice);
        }

        let minted_amount = if self.runtime_adapter.is_next_block_epoch_start(&prev_hash)? {
            Some(self.runtime_adapter.get_epoch_minted_amount(block.header().next_epoch_id())?)
        } else {
            None
        };

        if !block.verify_total_supply(prev_block.total_supply(), minted_amount) {
            byzantine_assert!(false);
            return Err(Error::InvalidGasPrice);
        }

        let (challenges_result, challenged_blocks) = self.verify_challenges(
            block.challenges(),
            block.header().epoch_id(),
            block.header().prev_hash(),
        )?;

        let prev_block = self.get_block(&prev_hash)?;

        self.validate_chunk_headers(&block, &prev_block)?;

        self.ping_missing_chunks(me, prev_hash, block)?;
        let incoming_receipts = self.collect_incoming_receipts_from_block(me, block)?;

        Ok(())
    }
}
